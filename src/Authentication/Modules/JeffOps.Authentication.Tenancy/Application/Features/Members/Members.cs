using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authentication.Tenancy.Domain;

namespace JeffOps.Authentication.Tenancy.Application.Features.Members;

public sealed record ListMembersQuery(TenancyActor Actor, Guid TenantId);

public sealed class ListMembersHandler(ITenantRepository tenants, IMembershipRepository memberships, IAccountRepository accounts)
    : IQueryHandler<ListMembersQuery, IReadOnlyList<MemberDto>>
{
    public async Task<Result<IReadOnlyList<MemberDto>>> HandleAsync(ListMembersQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (await tenants.FindAsync(query.TenantId, cancellationToken).ConfigureAwait(false) is null)
        {
            return Error.NotFound(TenancyErrors.NotFound, "No such tenant.");
        }

        var members = await memberships.ListForTenantAsync(query.TenantId, cancellationToken).ConfigureAwait(false);
        var emails = await accounts.FindEmailsAsync([.. members.Select(member => member.AccountId)], cancellationToken).ConfigureAwait(false);
        return Result.Success<IReadOnlyList<MemberDto>>([.. members.Select(member => member.ToDto(emails.GetValueOrDefault(member.AccountId)))]);
    }
}

/// <summary>An operator adds an existing account to a tenant (tenant administrators invite instead).</summary>
public sealed record AddMemberCommand(TenancyActor Actor, Guid TenantId, Guid AccountId, string Role);

public sealed class AddMemberHandler(
    ITenantRepository tenants,
    IMembershipRepository memberships,
    IAccountRepository accounts,
    ITenancyUnitOfWork unitOfWork,
    IAuditSink audit,
    TimeProvider time) : ICommandHandler<AddMemberCommand, MemberDto>
{
    public async Task<Result<MemberDto>> HandleAsync(AddMemberCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (!command.Actor.IsOperator)
        {
            return Error.Forbidden("not_allowed", "Tenant administrators add people with an invitation.");
        }

        if (!MemberRoles.TryParse(command.Role, out var role))
        {
            return Error.Failure("invalid_role", "The role is Member or Admin.");
        }

        if (await tenants.FindAsync(command.TenantId, cancellationToken).ConfigureAwait(false) is not { Status: not TenantStatus.Deleted })
        {
            return Error.NotFound(TenancyErrors.NotFound, "No such tenant.");
        }

        if (await accounts.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false) is not { } account)
        {
            return Error.NotFound(TenancyErrors.AccountNotFound, "No such account.");
        }

        var now = time.GetUtcNow();
        var membership = await memberships.FindAsync(command.TenantId, command.AccountId, cancellationToken).ConfigureAwait(false);
        if (membership is null)
        {
            membership = Membership.Create(command.TenantId, command.AccountId, role, MembershipSource.Operator, command.Actor.AccountId, now);
            memberships.Add(membership);
        }
        else
        {
            membership.ChangeRole(role);
        }

        if (!await unitOfWork.TrySaveUniqueAsync(cancellationToken).ConfigureAwait(false))
        {
            return Error.Conflict("member_conflict", "The membership changed meanwhile. Try again.");
        }

        await audit.WriteAsync(MemberAudit.Record("tenant.member_added", command.Actor, command.TenantId, command.AccountId, now, role), cancellationToken).ConfigureAwait(false);
        return membership.ToDto(account.Email);
    }
}

public sealed record SetMemberRoleCommand(TenancyActor Actor, Guid TenantId, Guid AccountId, string Role);

public sealed class SetMemberRoleHandler(
    IMembershipRepository memberships,
    IAccountRepository accounts,
    ITenancyUnitOfWork unitOfWork,
    IAuditSink audit,
    TimeProvider time) : ICommandHandler<SetMemberRoleCommand, MemberDto>
{
    public async Task<Result<MemberDto>> HandleAsync(SetMemberRoleCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (!MemberRoles.TryParse(command.Role, out var role))
        {
            return Error.Failure("invalid_role", "The role is Member or Admin.");
        }

        if (await memberships.FindAsync(command.TenantId, command.AccountId, cancellationToken).ConfigureAwait(false) is not { } membership)
        {
            return Error.NotFound(TenancyErrors.MemberNotFound, "That account isn't a member of this tenant.");
        }

        if (membership.Role == role)
        {
            return membership.ToDto((await accounts.FindEmailsAsync([command.AccountId], cancellationToken).ConfigureAwait(false)).GetValueOrDefault(command.AccountId));
        }

        if (membership.IsAdmin && !command.Actor.IsOperator && await memberships.CountAdminsAsync(command.TenantId, cancellationToken).ConfigureAwait(false) <= 1)
        {
            return Error.Conflict(TenancyErrors.LastAdmin, "A tenant needs at least one administrator. Make someone else administrator first.");
        }

        membership.ChangeRole(role);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        var now = time.GetUtcNow();
        await audit.WriteAsync(MemberAudit.Record("tenant.member_role_changed", command.Actor, command.TenantId, command.AccountId, now, role), cancellationToken).ConfigureAwait(false);
        return membership.ToDto((await accounts.FindEmailsAsync([command.AccountId], cancellationToken).ConfigureAwait(false)).GetValueOrDefault(command.AccountId));
    }
}

/// <summary>Ends a membership; the member's next token refresh no longer carries the tenant.</summary>
public sealed record RemoveMemberCommand(TenancyActor Actor, Guid TenantId, Guid AccountId);

public sealed class RemoveMemberHandler(IMembershipRepository memberships, ITenancyUnitOfWork unitOfWork, IAuditSink audit, TimeProvider time)
    : ICommandHandler<RemoveMemberCommand>
{
    public async Task<Result> HandleAsync(RemoveMemberCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (await memberships.FindAsync(command.TenantId, command.AccountId, cancellationToken).ConfigureAwait(false) is not { } membership)
        {
            return Error.NotFound(TenancyErrors.MemberNotFound, "That account isn't a member of this tenant.");
        }

        if (membership.IsAdmin && !command.Actor.IsOperator && await memberships.CountAdminsAsync(command.TenantId, cancellationToken).ConfigureAwait(false) <= 1)
        {
            return Error.Conflict(TenancyErrors.LastAdmin, "A tenant needs at least one administrator. Make someone else administrator first.");
        }

        memberships.Remove(membership);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(MemberAudit.Record("tenant.member_removed", command.Actor, command.TenantId, command.AccountId, time.GetUtcNow(), role: null), cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

internal static class MemberRoles
{
    public static bool TryParse(string? value, out MembershipRole role) =>
        Enum.TryParse(value, ignoreCase: true, out role) && Enum.IsDefined(role) && !int.TryParse(value, out _);
}

internal static class MemberAudit
{
    public static AuditRecord Record(string action, TenancyActor actor, Guid tenantId, Guid accountId, DateTimeOffset now, MembershipRole? role) =>
        new(action, "tenant_member", $"{tenantId}/{accountId}")
        {
            ActorId = actor.AccountId,
            TenantId = tenantId,
            OccurredAt = now,
            Severity = role == MembershipRole.Admin || action.EndsWith("removed", StringComparison.Ordinal) ? AuditSeverity.Warning : AuditSeverity.Information,
            Details = new Dictionary<string, string?> { ["account"] = accountId.ToString(), ["role"] = role?.ToString(), ["by_operator"] = actor.IsOperator ? "true" : "false" },
        };
}

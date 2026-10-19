using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authentication.Tenancy.Domain;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Tenancy.Application.Features.Invitations;

/// <summary>An invitation as listed: never its token.</summary>
public sealed record InvitationDto(Guid Id, string? Email, string Role, string State, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, Guid? AcceptedBy);

/// <summary>A new invitation with its token, shown this once; the endpoint turns it into a link.</summary>
public sealed record CreatedInvitation(InvitationDto Invitation, string Token);

/// <summary>What the invitee sees before accepting.</summary>
public sealed record InvitationPreview(Guid TenantId, string TenantName, string Role, string? Email, DateTimeOffset ExpiresAt);

internal static class InvitationMapping
{
    public static InvitationDto ToDto(this Invitation invitation, DateTimeOffset now) =>
        new(invitation.Id, invitation.Email, invitation.Role.ToString(), invitation.State(now), invitation.CreatedAt, invitation.ExpiresAt, invitation.AcceptedBy);

    public static bool TryParseRole(string? value, out MembershipRole role) =>
        Enum.TryParse(value ?? nameof(MembershipRole.Member), ignoreCase: true, out role) && Enum.IsDefined(role) && !int.TryParse(value, out _);
}

public sealed record CreateInvitationCommand(TenancyActor Actor, Guid TenantId, string? Email, string? Role);

public sealed class CreateInvitationHandler(
    ITenantRepository tenants,
    IInvitationRepository invitations,
    ITenancyUnitOfWork unitOfWork,
    IAuditSink audit,
    IOptions<TenancyOptions> options,
    TimeProvider time) : ICommandHandler<CreateInvitationCommand, CreatedInvitation>
{
    public async Task<Result<CreatedInvitation>> HandleAsync(CreateInvitationCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (!InvitationMapping.TryParseRole(command.Role, out var role))
        {
            return Error.Failure("invalid_role", "The role is Member or Admin.");
        }

        if (command.Email is { } email && (email.Trim().Length > Invitation.MaxEmailLength || (email.Trim().Length > 0 && !email.Contains('@', StringComparison.Ordinal))))
        {
            return Error.Failure(TenancyErrors.InvalidEmail, "That is not an email address.");
        }

        if (await tenants.FindAsync(command.TenantId, cancellationToken).ConfigureAwait(false) is not { } tenant)
        {
            return Error.NotFound(TenancyErrors.NotFound, "No such tenant.");
        }

        if (!tenant.AcceptsSessions)
        {
            return Error.Conflict(TenancyErrors.TenantClosed, "This tenant is suspended or deleted.");
        }

        var now = time.GetUtcNow();
        if (await invitations.CountOpenAsync(command.TenantId, now, cancellationToken).ConfigureAwait(false) >= options.Value.MaxOpenInvitationsPerTenant)
        {
            return Error.Failure(TenancyErrors.TooManyInvitations, $"A tenant can have at most {options.Value.MaxOpenInvitationsPerTenant} open invitations. Revoke some first.");
        }

        var (invitation, token) = Invitation.Create(command.TenantId, command.Email, role, command.Actor.AccountId, now, options.Value.InvitationLifetime);
        invitations.Add(invitation);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("tenant.invitation_created", "tenant_invitation", invitation.Id.ToString())
        {
            ActorId = command.Actor.AccountId,
            TenantId = command.TenantId,
            OccurredAt = now,
            Severity = role == MembershipRole.Admin ? AuditSeverity.Warning : AuditSeverity.Information,
            Details = new Dictionary<string, string?> { ["role"] = role.ToString(), ["email"] = invitation.Email },
        }, cancellationToken).ConfigureAwait(false);
        return new CreatedInvitation(invitation.ToDto(now), token);
    }
}

public sealed record ListInvitationsQuery(TenancyActor Actor, Guid TenantId);

public sealed class ListInvitationsHandler(IInvitationRepository invitations, TimeProvider time) : IQueryHandler<ListInvitationsQuery, IReadOnlyList<InvitationDto>>
{
    public async Task<Result<IReadOnlyList<InvitationDto>>> HandleAsync(ListInvitationsQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var now = time.GetUtcNow();
        return Result.Success<IReadOnlyList<InvitationDto>>(
            [.. (await invitations.ListForTenantAsync(query.TenantId, cancellationToken).ConfigureAwait(false)).Select(invitation => invitation.ToDto(now))]);
    }
}

public sealed record RevokeInvitationCommand(TenancyActor Actor, Guid TenantId, Guid InvitationId);

public sealed class RevokeInvitationHandler(IInvitationRepository invitations, ITenancyUnitOfWork unitOfWork, IAuditSink audit, TimeProvider time)
    : ICommandHandler<RevokeInvitationCommand>
{
    public async Task<Result> HandleAsync(RevokeInvitationCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (await invitations.FindAsync(command.InvitationId, cancellationToken).ConfigureAwait(false) is not { } invitation || invitation.TenantId != command.TenantId)
        {
            return Error.NotFound(TenancyErrors.InvitationNotFound, "No such invitation.");
        }

        var now = time.GetUtcNow();
        invitation.Revoke(now);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("tenant.invitation_revoked", "tenant_invitation", invitation.Id.ToString())
        {
            ActorId = command.Actor.AccountId,
            TenantId = command.TenantId,
            OccurredAt = now,
        }, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

/// <summary>What an open invitation offers; any other token (unknown, used, revoked, expired) gives the same answer.</summary>
public sealed record PreviewInvitationQuery(string Token);

public sealed class PreviewInvitationHandler(IInvitationRepository invitations, ITenantRepository tenants, TimeProvider time)
    : IQueryHandler<PreviewInvitationQuery, InvitationPreview>
{
    public async Task<Result<InvitationPreview>> HandleAsync(PreviewInvitationQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        return await OpenInvitation.FindAsync(invitations, tenants, query.Token, time.GetUtcNow(), cancellationToken).ConfigureAwait(false) is { } found
            ? new InvitationPreview(found.Tenant.Id, found.Tenant.Name, found.Invitation.Role.ToString(), found.Invitation.Email, found.Invitation.ExpiresAt)
            : OpenInvitation.Invalid;
    }
}

/// <summary>The signed-in account accepts an invitation and becomes a member (an existing member keeps the higher role).</summary>
public sealed record AcceptInvitationCommand(Guid AccountId, string Token);

public sealed class AcceptInvitationHandler(
    IInvitationRepository invitations,
    ITenantRepository tenants,
    IMembershipRepository memberships,
    ITenancyUnitOfWork unitOfWork,
    IAuditSink audit,
    TimeProvider time) : ICommandHandler<AcceptInvitationCommand, InvitationPreview>
{
    public async Task<Result<InvitationPreview>> HandleAsync(AcceptInvitationCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var now = time.GetUtcNow();
        if (await OpenInvitation.FindAsync(invitations, tenants, command.Token, now, cancellationToken).ConfigureAwait(false) is not { } found)
        {
            return OpenInvitation.Invalid;
        }

        var (invitation, tenant) = found;

        invitation.TryAccept(command.AccountId, now);
        if (await memberships.FindAsync(tenant.Id, command.AccountId, cancellationToken).ConfigureAwait(false) is { } existing)
        {
            existing.RaiseTo(invitation.Role);
        }
        else
        {
            memberships.Add(Membership.Create(tenant.Id, command.AccountId, invitation.Role, MembershipSource.Invitation, invitation.CreatedBy, now));
        }

        if (!await unitOfWork.TrySaveUniqueAsync(cancellationToken).ConfigureAwait(false))
        {
            return Error.Conflict("member_conflict", "The membership changed meanwhile. Open the invitation again.");
        }

        await audit.WriteAsync(new AuditRecord("tenant.invitation_accepted", "tenant_invitation", invitation.Id.ToString())
        {
            ActorId = command.AccountId,
            TenantId = tenant.Id,
            OccurredAt = now,
            Severity = invitation.Role == MembershipRole.Admin ? AuditSeverity.Warning : AuditSeverity.Information,
            Details = new Dictionary<string, string?> { ["role"] = invitation.Role.ToString(), ["invited_by"] = invitation.CreatedBy.ToString() },
        }, cancellationToken).ConfigureAwait(false);
        return new InvitationPreview(tenant.Id, tenant.Name, invitation.Role.ToString(), invitation.Email, invitation.ExpiresAt);
    }
}

internal static class OpenInvitation
{
    public static readonly Error Invalid =
        Error.NotFound(TenancyErrors.InvitationInvalid, "This invitation link doesn't work (anymore). Ask for a new one.");

    public static async Task<OpenInvitationMatch?> FindAsync(
        IInvitationRepository invitations, ITenantRepository tenants, string? token, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 100
            || await invitations.FindByTokenHashAsync(Invitation.Hash(token), cancellationToken).ConfigureAwait(false) is not { } invitation
            || !invitation.IsOpen(now)
            || await tenants.FindAsync(invitation.TenantId, cancellationToken).ConfigureAwait(false) is not { AcceptsSessions: true } tenant)
        {
            return null;
        }

        return new OpenInvitationMatch(invitation, tenant);
    }
}

internal sealed record OpenInvitationMatch(Invitation Invitation, Tenant Tenant);

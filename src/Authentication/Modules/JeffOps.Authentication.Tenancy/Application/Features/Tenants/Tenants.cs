using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authentication.Tenancy.Domain;

namespace JeffOps.Authentication.Tenancy.Application.Features.Tenants;

/// <summary>An operator creates a tenant; with <paramref name="FirstAdmin"/>, that account becomes its administrator.</summary>
public sealed record CreateTenantCommand(TenancyActor Actor, string Name, Guid? FirstAdmin);

public sealed class CreateTenantHandler(
    ITenantRepository tenants,
    IMembershipRepository memberships,
    Authentication.Application.Abstractions.IAccountRepository accounts,
    ITenancyUnitOfWork unitOfWork,
    IAuditSink audit,
    TimeProvider time) : ICommandHandler<CreateTenantCommand, TenantDto>
{
    public async Task<Result<TenantDto>> HandleAsync(CreateTenantCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (!command.Actor.IsOperator)
        {
            return Error.Forbidden("not_allowed", "Only platform operators create tenants this way.");
        }

        if (Tenant.NormalizeName(command.Name) is null)
        {
            return Error.Failure(TenancyErrors.InvalidName, $"A tenant needs a name of at most {Tenant.MaxNameLength} characters.");
        }

        if (command.FirstAdmin is { } admin && await accounts.FindAsync(admin, cancellationToken).ConfigureAwait(false) is null)
        {
            return Error.NotFound(TenancyErrors.AccountNotFound, "No such account.");
        }

        var now = time.GetUtcNow();
        var tenant = Tenant.Create(command.Name, command.Actor.AccountId, now);
        tenants.Add(tenant);
        if (command.FirstAdmin is { } first)
        {
            memberships.Add(Membership.Create(tenant.Id, first, MembershipRole.Admin, MembershipSource.Operator, command.Actor.AccountId, now));
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("tenant.created", "tenant", tenant.Id.ToString())
        {
            ActorId = command.Actor.AccountId,
            TenantId = tenant.Id,
            OccurredAt = now,
            Severity = AuditSeverity.Warning,
            Details = new Dictionary<string, string?> { ["name"] = tenant.Name, ["first_admin"] = command.FirstAdmin?.ToString() },
        }, cancellationToken).ConfigureAwait(false);
        return tenant.ToDto();
    }
}

public sealed record ListTenantsQuery(TenancyActor Actor, string? NameContains, int Skip, int Take);

public sealed class ListTenantsHandler(ITenantRepository tenants) : IQueryHandler<ListTenantsQuery, IReadOnlyList<TenantDto>>
{
    public const int MaxTake = 200;

    public async Task<Result<IReadOnlyList<TenantDto>>> HandleAsync(ListTenantsQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (!query.Actor.IsOperator)
        {
            return Error.Forbidden("not_allowed", "Only platform operators list tenants.");
        }

        var found = await tenants.ListAsync(query.NameContains, Math.Max(0, query.Skip), Math.Clamp(query.Take, 1, MaxTake), cancellationToken).ConfigureAwait(false);
        return Result.Success<IReadOnlyList<TenantDto>>([.. found.Select(tenant => tenant.ToDto())]);
    }
}

public sealed record GetTenantQuery(TenancyActor Actor, Guid TenantId);

public sealed class GetTenantHandler(ITenantRepository tenants) : IQueryHandler<GetTenantQuery, TenantDto>
{
    public async Task<Result<TenantDto>> HandleAsync(GetTenantQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        return await tenants.FindAsync(query.TenantId, cancellationToken).ConfigureAwait(false) is { } tenant
            ? tenant.ToDto()
            : Error.NotFound(TenancyErrors.NotFound, "No such tenant.");
    }
}

/// <summary>Renames a tenant, or (operators only) suspends, resumes or deletes it.</summary>
public sealed record UpdateTenantCommand(TenancyActor Actor, Guid TenantId, string? Name, string? Status);

public sealed class UpdateTenantHandler(ITenantRepository tenants, ITenancyUnitOfWork unitOfWork, IAuditSink audit, TimeProvider time)
    : ICommandHandler<UpdateTenantCommand, TenantDto>
{
    public async Task<Result<TenantDto>> HandleAsync(UpdateTenantCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (await tenants.FindAsync(command.TenantId, cancellationToken).ConfigureAwait(false) is not { } tenant)
        {
            return Error.NotFound(TenancyErrors.NotFound, "No such tenant.");
        }

        if (tenant.Status == TenantStatus.Deleted)
        {
            return Error.Conflict(TenancyErrors.TenantClosed, "This tenant was deleted.");
        }

        var now = time.GetUtcNow();
        var changes = new Dictionary<string, string?>();
        if (command.Name is not null)
        {
            if (Tenant.NormalizeName(command.Name) is not { } name)
            {
                return Error.Failure(TenancyErrors.InvalidName, $"A tenant needs a name of at most {Tenant.MaxNameLength} characters.");
            }

            changes["name"] = name;
            tenant.Rename(name);
        }

        if (command.Status is not null)
        {
            if (!command.Actor.IsOperator)
            {
                return Error.Forbidden("not_allowed", "Only platform operators suspend, resume or delete tenants.");
            }

            if (!Enum.TryParse<TenantStatus>(command.Status, ignoreCase: true, out var status) || !Enum.IsDefined(status)
                || !tenant.TryChangeStatus(status, now))
            {
                return Error.Failure(TenancyErrors.InvalidStatus, "That status change isn't possible (a deleted tenant stays deleted; the platform tenant stays active).");
            }

            changes["status"] = status.ToString();
        }

        if (changes.Count == 0)
        {
            return tenant.ToDto();
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("tenant.updated", "tenant", tenant.Id.ToString())
        {
            ActorId = command.Actor.AccountId,
            TenantId = tenant.Id,
            OccurredAt = now,
            Severity = changes.ContainsKey("status") ? AuditSeverity.Warning : AuditSeverity.Information,
            Details = changes,
        }, cancellationToken).ConfigureAwait(false);
        return tenant.ToDto();
    }
}

/// <summary>A tenant the caller belongs to, with their role: what a product shows in a tenant switcher.</summary>
public sealed record MyTenantDto(Guid TenantId, string Name, string Role, string Status);

public sealed record ListMyTenantsQuery(Guid AccountId);

public sealed class ListMyTenantsHandler(IMembershipRepository memberships, ITenantRepository tenants) : IQueryHandler<ListMyTenantsQuery, IReadOnlyList<MyTenantDto>>
{
    public async Task<Result<IReadOnlyList<MyTenantDto>>> HandleAsync(ListMyTenantsQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var mine = await memberships.ListForAccountAsync(query.AccountId, cancellationToken).ConfigureAwait(false);
        var byId = await tenants.FindManyAsync([.. mine.Select(membership => membership.TenantId)], cancellationToken).ConfigureAwait(false);
        return Result.Success<IReadOnlyList<MyTenantDto>>([.. mine
            .Where(membership => byId.TryGetValue(membership.TenantId, out var tenant) && tenant.Status != TenantStatus.Deleted)
            .Select(membership => new MyTenantDto(membership.TenantId, byId[membership.TenantId].Name, membership.Role.ToString(), byId[membership.TenantId].Status.ToString()))]);
    }
}

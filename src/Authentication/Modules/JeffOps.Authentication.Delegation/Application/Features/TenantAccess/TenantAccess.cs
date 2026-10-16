using JeffOps.Authentication.Delegation.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Delegation.Application.Features.TenantAccess;

public sealed record TenantAccessGrantDto(
    Guid Id,
    Guid ActorUserId,
    Guid? ActorOrganizationId,
    Guid TargetTenantId,
    string Status,
    DateTimeOffset RequestedAt,
    DateTimeOffset ApprovalDeadline,
    DateTimeOffset? ApprovedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? EndedAt);

internal static class TenantAccessMapping
{
    public static TenantAccessGrantDto ToDto(this TenantAccessGrant grant) => new(
        grant.Id, grant.ActorUserId, grant.ActorOrganizationId, grant.TargetTenantId, grant.Status.ToString(),
        grant.RequestedAt, grant.ApprovalDeadline, grant.ApprovedAt, grant.ExpiresAt, grant.EndedAt);
}

// ---- Request (partner user) --------------------------------------------------------------------------------------------

/// <summary>
/// A partner's user asks for access to a lockbox tenant their organization manages. Idempotent: an open grant for the same
/// tenant is returned instead of a new one, so clients can poll by asking again.
/// </summary>
public sealed record RequestTenantAccessCommand(DelegationCaller Caller, Guid TenantId);

public sealed class RequestTenantAccessHandler(
    ITenantAccessGrantRepository grants,
    IDelegationDirectory directory,
    IDelegationUnitOfWork unitOfWork,
    IOptions<DelegationOptions> options,
    TimeProvider time) : ICommandHandler<RequestTenantAccessCommand, TenantAccessGrantDto>
{
    public async Task<Result<TenantAccessGrantDto>> HandleAsync(RequestTenantAccessCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var caller = command.Caller;

        if (!caller.IsHomeSession)
        {
            return DelegationErrors.HomeSession();
        }

        if (caller.OrganizationId is not { } organization)
        {
            return Error.Forbidden(DelegationErrors.OrganizationRequired, "Your session belongs to no organization.");
        }

        var scopes = await DirectoryCalls.ScopesAsync(directory, organization, command.TenantId, cancellationToken).ConfigureAwait(false);
        if (scopes.IsFailure)
        {
            return scopes.Error;
        }

        if (scopes.Value.Count == 0)
        {
            return Error.Forbidden(DelegationErrors.NotManaged, "Your organization doesn't manage this tenant.");
        }

        var required = await DirectoryCalls.RequiresApprovalAsync(directory, command.TenantId, cancellationToken).ConfigureAwait(false);
        if (required.IsFailure)
        {
            return required.Error;
        }

        if (!required.Value)
        {
            return Error.Failure(DelegationErrors.ApprovalNotRequired, "This tenant doesn't require approval; switch to it directly.");
        }

        var now = time.GetUtcNow();
        var open = await grants.ListOpenAsync(caller.UserId, command.TenantId, now, cancellationToken).ConfigureAwait(false);
        if (open.FirstOrDefault(grant => grant.ActorUserId == caller.UserId && grant.TargetTenantId == command.TenantId) is { } existing)
        {
            return existing.ToDto();
        }

        var created = TenantAccessGrant.Request(caller.UserId, organization, command.TenantId, now, options.Value.TenantAccess.ApprovalWindow);
        grants.Add(created);
        await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return created.ToDto();
    }
}

// ---- Decide (tenant administrator) -------------------------------------------------------------------------------------

/// <summary>
/// An administrator of the tenant approves or denies. <paramref name="MayApprove"/> is the outcome of the host's approval
/// policy for the caller in their own tenant.
/// </summary>
public sealed record DecideTenantAccessCommand(DelegationCaller Caller, Guid GrantId, bool Approve, bool MayApprove);

public sealed class DecideTenantAccessHandler(
    ITenantAccessGrantRepository grants,
    IDelegationUnitOfWork unitOfWork,
    IOptions<DelegationOptions> options,
    TimeProvider time) : ICommandHandler<DecideTenantAccessCommand, TenantAccessGrantDto>
{
    public async Task<Result<TenantAccessGrantDto>> HandleAsync(DecideTenantAccessCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var caller = command.Caller;
        if (!caller.IsHomeSession)
        {
            return DelegationErrors.HomeSession();
        }

        var grant = await grants.FindAsync(command.GrantId, cancellationToken).ConfigureAwait(false);
        if (grant is null || grant.TargetTenantId != caller.TenantId)
        {
            return Error.NotFound(DelegationErrors.NotFound, "No such request in your tenant.");
        }

        if (!command.MayApprove)
        {
            return Error.Forbidden(DelegationErrors.NotAllowed, "You are not allowed to decide access to this tenant.");
        }

        if (grant.ActorUserId == caller.UserId)
        {
            return Error.Forbidden(DelegationErrors.NotAllowed, "You can't decide your own request.");
        }

        // The expiry sweep (or another decision) may change the grant at the same moment: decide again on its new state.
        var now = time.GetUtcNow();
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var decided = command.Approve ? grant.Approve(caller.UserId, now, options.Value.TenantAccess.SessionWindow) : grant.Deny(now);
            if (await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
            {
                return decided
                    ? grant.ToDto()
                    : Error.Failure(DelegationErrors.NotPending, "The request can no longer be decided.");
            }

            await unitOfWork.ReloadAsync(grant, cancellationToken).ConfigureAwait(false);
        }

        return DelegationErrors.Concurrent();
    }
}

// ---- End / revoke ------------------------------------------------------------------------------------------------------

/// <summary>
/// The actor ends their access, or a tenant administrator (<paramref name="MayApprove"/> in the grant's tenant) revokes it.
/// </summary>
public sealed record EndTenantAccessCommand(DelegationCaller Caller, Guid GrantId, bool Revoke, bool MayApprove);

public sealed class EndTenantAccessHandler(ITenantAccessGrantRepository grants, IDelegationUnitOfWork unitOfWork, TimeProvider time)
    : ICommandHandler<EndTenantAccessCommand, TenantAccessGrantDto>
{
    public async Task<Result<TenantAccessGrantDto>> HandleAsync(EndTenantAccessCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var caller = command.Caller;

        var grant = await grants.FindAsync(command.GrantId, cancellationToken).ConfigureAwait(false);
        var isActor = grant is not null && grant.ActorUserId == caller.UserId;
        var isAdministrator = grant is not null && grant.TargetTenantId == caller.TenantId && caller.IsHomeSession && command.MayApprove;
        if (grant is null || !(isActor || isAdministrator))
        {
            return Error.NotFound(DelegationErrors.NotFound, "No such grant.");
        }

        var now = time.GetUtcNow();
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var changed = command.Revoke ? grant.Revoke(now) : grant.End(now);
            if (!changed)
            {
                return Error.Failure(DelegationErrors.NotLive, command.Revoke ? "The grant is already over." : "The grant is not live.");
            }

            if (await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
            {
                return grant.ToDto();
            }

            await unitOfWork.ReloadAsync(grant, cancellationToken).ConfigureAwait(false);
        }

        return DelegationErrors.Concurrent();
    }
}

// ---- Queries -----------------------------------------------------------------------------------------------------------

/// <summary>
/// Open grants the caller can see: their own requests, and — for administrators (<paramref name="MayApprove"/>) — requests
/// into their tenant.
/// </summary>
public sealed record ListTenantAccessQuery(DelegationCaller Caller, bool MayApprove);

public sealed record TenantAccessOverview(IReadOnlyList<TenantAccessGrantDto> Mine, IReadOnlyList<TenantAccessGrantDto> IntoMyTenant);

public sealed class ListTenantAccessHandler(ITenantAccessGrantRepository grants, TimeProvider time) : IQueryHandler<ListTenantAccessQuery, TenantAccessOverview>
{
    public async Task<Result<TenantAccessOverview>> HandleAsync(ListTenantAccessQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var caller = query.Caller;
        var now = time.GetUtcNow();

        var mine = await grants.ListOpenAsync(caller.UserId, null, now, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<TenantAccessGrant> incoming = query.MayApprove && caller.IsHomeSession && caller.TenantId is { } tenant
            ? await grants.ListOpenAsync(null, tenant, now, cancellationToken).ConfigureAwait(false)
            : [];

        return new TenantAccessOverview([.. mine.Select(grant => grant.ToDto())], [.. incoming.Select(grant => grant.ToDto())]);
    }
}

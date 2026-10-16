using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Delegation.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Delegation.Application.Features.Impersonation;

public sealed record ImpersonationGrantDto(
    Guid Id,
    Guid ActorUserId,
    Guid? ActorOrganizationId,
    string ActorKind,
    Guid TargetUserId,
    Guid? TargetTenantId,
    string Status,
    bool BreakGlass,
    string? Reason,
    DateTimeOffset RequestedAt,
    DateTimeOffset ApprovalDeadline,
    DateTimeOffset? ApprovedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? EndedAt);

internal static class ImpersonationMapping
{
    public static ImpersonationGrantDto ToDto(this ImpersonationGrant grant) => new(
        grant.Id, grant.ActorUserId, grant.ActorOrganizationId, grant.ActorKind.ToString(), grant.TargetUserId, grant.TargetTenantId,
        grant.Status.ToString(), grant.BreakGlass, grant.Reason, grant.RequestedAt, grant.ApprovalDeadline, grant.ApprovedAt, grant.ExpiresAt, grant.EndedAt);
}

// ---- Request -----------------------------------------------------------------------------------------------------------

/// <summary>
/// Asks to act as <paramref name="TargetUserId"/>. The endpoint evaluates the host's authorization policies and passes the
/// outcome (<paramref name="MayInitiate"/>, <paramref name="MayBreakGlass"/>); the handler applies the rules.
/// </summary>
public sealed record RequestImpersonationCommand(DelegationCaller Caller, Guid TargetUserId, bool BreakGlass, string? Reason, bool MayInitiate, bool MayBreakGlass);

public sealed class RequestImpersonationHandler(
    IImpersonationGrantRepository grants,
    ITenantAccessGrantRepository tenantAccess,
    IAccountRepository accounts,
    IDelegationDirectory directory,
    SessionBuilder sessions,
    IDelegationUnitOfWork unitOfWork,
    IOptions<DelegationOptions> options,
    TimeProvider time) : ICommandHandler<RequestImpersonationCommand, ImpersonationGrantDto>
{
    public async Task<Result<ImpersonationGrantDto>> HandleAsync(RequestImpersonationCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var caller = command.Caller;
        var settings = options.Value.Impersonation;
        var now = time.GetUtcNow();

        if (!caller.IsHomeSession)
        {
            return DelegationErrors.HomeSession();
        }

        if (caller.UserId == command.TargetUserId)
        {
            return Error.Failure(DelegationErrors.SelfImpersonation, "You can't impersonate yourself.");
        }

        if (command.BreakGlass)
        {
            if (!caller.IsRoot)
            {
                return Error.Forbidden(DelegationErrors.BreakGlassPlatformOnly, "Break-glass impersonation is for platform administrators only.");
            }

            if (!command.MayBreakGlass)
            {
                return Error.Forbidden(DelegationErrors.NotAllowed, "You are not allowed to use break-glass impersonation.");
            }

            if (string.IsNullOrWhiteSpace(command.Reason))
            {
                return Error.Failure(DelegationErrors.ReasonRequired, "Break-glass impersonation needs a reason.");
            }
        }
        else if (!command.MayInitiate)
        {
            return Error.Forbidden(DelegationErrors.NotAllowed, "You are not allowed to impersonate users.");
        }

        var target = await accounts.FindAsync(command.TargetUserId, cancellationToken).ConfigureAwait(false);
        if (target is not { CanAuthenticate: true })
        {
            return Error.Failure(DelegationErrors.TargetInactive, "The user doesn't exist or is not active.");
        }

        var standing = await sessions.StandingAsync(target.Id, boundTenant: null, cancellationToken).ConfigureAwait(false);
        if (standing.IsFailure)
        {
            return standing.Error;
        }

        if (standing.Value.Membership?.Level == JeffOps.Authentication.Abstractions.Access.AccessLevel.Root)
        {
            return Error.Forbidden(DelegationErrors.TargetProtected, "Platform administrators can't be impersonated.");
        }

        var targetTenant = standing.Value.Membership?.TenantId;
        var kind = caller.IsRoot ? ActorKind.Platform : ActorKind.Partner;
        if (kind == ActorKind.Partner)
        {
            if (caller.OrganizationId is not { } organization || targetTenant is not { } tenant)
            {
                return Error.Forbidden(DelegationErrors.NotManaged, "Your organization doesn't manage this user's tenant.");
            }

            var managed = await DirectoryCalls.ScopesAsync(directory, organization, tenant, cancellationToken).ConfigureAwait(false);
            if (managed.IsFailure)
            {
                return managed.Error;
            }

            if (managed.Value.Count == 0)
            {
                return Error.Forbidden(DelegationErrors.NotManaged, "Your organization doesn't manage this user's tenant.");
            }

            // A lockbox tenant: its administrator's approval comes first, for impersonating its users as for switching in.
            var lockbox = await Tokens.ActorTokens.LockboxGrantAsync(tenantAccess, directory, caller.UserId, organization, tenant, now, cancellationToken).ConfigureAwait(false);
            if (lockbox.IsFailure)
            {
                return lockbox.Error.Code == DelegationErrors.TenantApprovalRequired ? Error.Forbidden(lockbox.Error.Code, lockbox.Error.Message) : lockbox.Error;
            }
        }

        var open = await grants.ListOpenAsync(caller.UserId, now, cancellationToken).ConfigureAwait(false);
        if (open.Any(grant => grant.ActorUserId == caller.UserId && grant.TargetUserId == target.Id))
        {
            return Error.Conflict(DelegationErrors.Duplicate, "You already have an open impersonation request for this user.");
        }

        var created = command.BreakGlass
            ? ImpersonationGrant.BreakGlassAccess(caller.UserId, caller.OrganizationId, target.Id, targetTenant, command.Reason!, now, settings.SessionWindow)
            : ImpersonationGrant.Request(caller.UserId, caller.OrganizationId, kind, target.Id, targetTenant, command.Reason, now, settings.ApprovalWindow);
        grants.Add(created);
        await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return created.ToDto();
    }
}

// ---- Decide (target) ---------------------------------------------------------------------------------------------------

/// <summary>The target approves or denies a request to act as them.</summary>
public sealed record DecideImpersonationCommand(DelegationCaller Caller, Guid GrantId, bool Approve);

public sealed class DecideImpersonationHandler(
    IImpersonationGrantRepository grants,
    IDelegationUnitOfWork unitOfWork,
    IOptions<DelegationOptions> options,
    TimeProvider time) : ICommandHandler<DecideImpersonationCommand, ImpersonationGrantDto>
{
    public async Task<Result<ImpersonationGrantDto>> HandleAsync(DecideImpersonationCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var caller = command.Caller;
        if (!caller.IsHomeSession)
        {
            return DelegationErrors.HomeSession();
        }

        var grant = await grants.FindAsync(command.GrantId, cancellationToken).ConfigureAwait(false);
        if (grant is null || grant.TargetUserId != caller.UserId)
        {
            return Error.NotFound(DelegationErrors.NotFound, "No such request.");
        }

        // The expiry sweep (or another decision) may change the grant at the same moment: decide again on its new state.
        var now = time.GetUtcNow();
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var decided = command.Approve ? grant.Approve(caller.UserId, now, options.Value.Impersonation.SessionWindow) : grant.Deny(now);
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

// ---- End / revoke (actor or target) ------------------------------------------------------------------------------------

/// <summary>
/// Ends a grant. <paramref name="Revoke"/> withdraws it whatever its state (the target's kill switch); otherwise only a live
/// grant ends. Either side may do either; impersonation sessions may end their own grant.
/// </summary>
public sealed record EndImpersonationCommand(Guid CallerUserId, Guid GrantId, bool Revoke);

public sealed class EndImpersonationHandler(IImpersonationGrantRepository grants, IDelegationUnitOfWork unitOfWork, TimeProvider time)
    : ICommandHandler<EndImpersonationCommand, ImpersonationGrantDto>
{
    public async Task<Result<ImpersonationGrantDto>> HandleAsync(EndImpersonationCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        var grant = await grants.FindAsync(command.GrantId, cancellationToken).ConfigureAwait(false);
        if (grant is null || (grant.ActorUserId != command.CallerUserId && grant.TargetUserId != command.CallerUserId))
        {
            return Error.NotFound(DelegationErrors.NotFound, "No such grant.");
        }

        var now = time.GetUtcNow();
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var changed = command.Revoke
                ? grant.Revoke(now, grant.TargetUserId == command.CallerUserId ? GrantEndReasons.RevokedByTarget : GrantEndReasons.Revoked)
                : grant.End(now);
            if (!changed)
            {
                return Error.Failure(DelegationErrors.NotLive, command.Revoke ? "The grant is already over." : "The grant is not live.");
            }

            if (await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
            {
                return grant.ToDto();
            }

            // Lost a race (a mint or a decision landed first): apply to the committed state once more.
            await unitOfWork.ReloadAsync(grant, cancellationToken).ConfigureAwait(false);
        }

        return DelegationErrors.Concurrent();
    }
}

// ---- Queries -----------------------------------------------------------------------------------------------------------

/// <summary>A grant, for its actor or target.</summary>
public sealed record GetImpersonationQuery(Guid CallerUserId, Guid GrantId);

public sealed class GetImpersonationHandler(IImpersonationGrantRepository grants) : IQueryHandler<GetImpersonationQuery, ImpersonationGrantDto>
{
    public async Task<Result<ImpersonationGrantDto>> HandleAsync(GetImpersonationQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var grant = await grants.FindAsync(query.GrantId, cancellationToken).ConfigureAwait(false);
        return grant is not null && (grant.ActorUserId == query.CallerUserId || grant.TargetUserId == query.CallerUserId)
            ? grant.ToDto()
            : Error.NotFound(DelegationErrors.NotFound, "No such grant.");
    }
}

/// <summary>The caller's open grants, as actor and as target: pending ones within their deadline, and live ones.</summary>
public sealed record ListImpersonationsQuery(Guid CallerUserId);

public sealed record ImpersonationOverview(IReadOnlyList<ImpersonationGrantDto> AsActor, IReadOnlyList<ImpersonationGrantDto> AsTarget);

public sealed class ListImpersonationsHandler(IImpersonationGrantRepository grants, TimeProvider time) : IQueryHandler<ListImpersonationsQuery, ImpersonationOverview>
{
    public async Task<Result<ImpersonationOverview>> HandleAsync(ListImpersonationsQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var open = await grants.ListOpenAsync(query.CallerUserId, time.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        return new ImpersonationOverview(
            [.. open.Where(grant => grant.ActorUserId == query.CallerUserId).Select(grant => grant.ToDto())],
            [.. open.Where(grant => grant.TargetUserId == query.CallerUserId).Select(grant => grant.ToDto())]);
    }
}

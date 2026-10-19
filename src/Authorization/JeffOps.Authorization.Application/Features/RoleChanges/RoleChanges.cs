using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Application.Management;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Management;
using JeffOps.Authorization.Domain.Permissions;

namespace JeffOps.Authorization.Application.Features.RoleChanges;

internal static class RoleChangeMapping
{
    public static RoleChangeRequestDto ToDto(this RoleChangeRequest request) => new(
        request.Id,
        request.Kind.ToString(),
        request.RoleId,
        request.PermissionCode,
        request.TenantId,
        request.RequestedBy,
        request.RequestedAt,
        request.Status.ToString(),
        request.DecidedBy,
        request.DecidedAt,
        request.Note,
        request.TargetUserId,
        request.ScopeKey,
        request.ExpiresAt);
}

// ---- ListRoleChanges ---------------------------------------------------------------------------------------------------

public sealed record ListRoleChangesQuery(ManagementCaller Caller, RoleChangeStatus? Status);

public sealed class ListRoleChangesHandler(IRoleChangeRepository changes, ManagementGuard guard) : IQueryHandler<ListRoleChangesQuery, IReadOnlyList<RoleChangeRequestDto>>
{
    public async Task<Result<IReadOnlyList<RoleChangeRequestDto>>> HandleAsync(ListRoleChangesQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var caller = query.Caller;

        if (!caller.IsRoot)
        {
            if (caller.EffectiveTenantId is not { } tenant)
            {
                return Error.Forbidden(ManagementErrors.NotYourTenant, "Your session acts in no tenant.");
            }

            if (await guard.RequireAsync(caller, tenant, guard.Options.Permissions.RolesRead, cancellationToken).ConfigureAwait(false) is { } refused)
            {
                return refused;
            }
        }

        var list = await changes.ListAsync(caller.EffectiveTenantId, allTenants: caller.IsRoot, query.Status, cancellationToken).ConfigureAwait(false);
        return list.OrderByDescending(request => request.RequestedAt).Select(request => request.ToDto()).ToList();
    }
}

// ---- DecideRoleChange --------------------------------------------------------------------------------------------------

/// <summary>Approves (and applies) or rejects a pending change. Never by the requester.</summary>
public sealed record DecideRoleChangeCommand(ManagementCaller Caller, Guid RequestId, bool Approve, string? Note);

public sealed class DecideRoleChangeHandler(
    IRoleChangeRepository changes,
    IRoleRepository roles,
    IUnitOfWork unitOfWork,
    ManagementGuard guard,
    HeldPermissions held,
    RoleChangeApplier applier,
    ManagementAudit audit,
    TimeProvider time) : ICommandHandler<DecideRoleChangeCommand, RoleChangeRequestDto>
{
    public async Task<Result<RoleChangeRequestDto>> HandleAsync(DecideRoleChangeCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var caller = command.Caller;

        var request = await changes.FindAsync(command.RequestId, cancellationToken).ConfigureAwait(false);
        if (request is null || (!caller.IsRoot && request.TenantId != caller.EffectiveTenantId))
        {
            return Error.NotFound(ManagementErrors.NotFound, "No such request.");
        }

        if (request.Status != RoleChangeStatus.Pending)
        {
            return Error.Conflict(ManagementErrors.AlreadyDecided, "The request has already been decided.");
        }

        if (caller.UserId is not { } decider || decider == request.RequestedBy)
        {
            return Error.Forbidden(ManagementErrors.SelfDecision, "A request must be decided by someone other than the requester.");
        }

        // The approver must be able to make the change themselves.
        var permission = request.Kind == RoleChangeKind.AssignRole ? guard.Options.Permissions.AssignmentsWrite : guard.Options.Permissions.RolesWrite;
        if (request.TenantId is { } tenant
            && await guard.RequireAsync(caller, tenant, permission, cancellationToken).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        if (command.Approve && time.GetUtcNow() - request.RequestedAt > guard.Options.RoleChangeRequestLifetime)
        {
            return Error.Failure(ManagementErrors.Expired, "This request is too old to approve; reject it and ask again.");
        }

        if (command.Approve && request.Kind == RoleChangeKind.AddPermission && request.PermissionCode is { } added && request.TenantId is { } changeTenant)
        {
            // Both sides must still be able to make the change: the approver holds the permission being added, and the
            // requester still holds the right to request it.
            if (!caller.IsRoot
                && !Permission.GrantsAny(await held.OfCallerAsync(caller, changeTenant, "tenant", null, cancellationToken).ConfigureAwait(false), added))
            {
                return Error.Forbidden(ManagementErrors.Escalation, $"You can't approve adding {added}: you don't hold it.");
            }

            if (!Permission.GrantsAny(await held.OfAsync(request.RequestedBy, changeTenant, "tenant", null, cancellationToken).ConfigureAwait(false), guard.Options.Permissions.RolesWrite))
            {
                return Error.Forbidden(ManagementErrors.RequesterLacksPermission, "The requester no longer holds the permission to make this change.");
            }
        }

        if (command.Approve && request.Kind == RoleChangeKind.AssignRole && !caller.IsRoot
            && await roles.FindAsync(request.RoleId!.Value, cancellationToken).ConfigureAwait(false) is { } role)
        {
            var holds = await held.OfCallerAsync(caller, request.TenantId!.Value, request.ScopeKey!, request.ScopeInstanceId, cancellationToken).ConfigureAwait(false);
            if (AssignmentRules.CeilingViolations(role, holds, grantingToSelf: decider == request.TargetUserId, guard.Options.PrivilegedPermissions()) is { Count: > 0 } missing)
            {
                return Error.Forbidden(ManagementErrors.Escalation, $"You can't approve '{role.Name}': it carries permissions you don't hold ({string.Join(", ", missing.Take(5))}).");
            }
        }

        request.Decide(command.Approve, decider, command.Note, time.GetUtcNow());
        if (command.Approve && await applier.ApplyAsync(request, decider, cancellationToken).ConfigureAwait(false) is { } failed)
        {
            return failed;
        }

        // The status is a concurrency token: of two decisions racing, one is saved and the other answers conflict.
        if (!await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
        {
            return Error.Conflict(ManagementErrors.AlreadyDecided, "The request has already been decided.");
        }
        await audit.WriteAsync(command.Approve ? "role.change.approved" : "role.change.rejected", "role_change", request.Id.ToString(), caller, request.TenantId, cancellationToken).ConfigureAwait(false);
        return request.ToDto();
    }
}

// ---- Approval setting --------------------------------------------------------------------------------------------------

public sealed record GetApprovalSettingQuery(ManagementCaller Caller);

public sealed class GetApprovalSettingHandler(IApprovalSettingRepository settings, ManagementGuard guard) : IQueryHandler<GetApprovalSettingQuery, ApprovalSettingDto>
{
    public async Task<Result<ApprovalSettingDto>> HandleAsync(GetApprovalSettingQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var caller = query.Caller;
        var tenantId = caller.IsRoot ? null : caller.EffectiveTenantId;

        if (!caller.IsRoot && tenantId is { } tenant
            && await guard.RequireAsync(caller, tenant, guard.Options.Permissions.RolesRead, cancellationToken).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        var global = await settings.GetAsync(null, cancellationToken).ConfigureAwait(false);
        var tenantSetting = tenantId is { } id ? await settings.GetAsync(id, cancellationToken).ConfigureAwait(false) : null;
        return new ApprovalSettingDto(global?.RequireApproval ?? true, tenantSetting?.RequireApproval, ApprovalSetting.Effective(tenantSetting, global));
    }
}

/// <summary>
/// Turns four-eyes approval on or off for the caller's tenant (or globally, Root only). Turning it on applies at once;
/// turning it off while it is on is itself a change that needs a second approver (a ratchet).
/// </summary>
public sealed record SetApprovalSettingCommand(ManagementCaller Caller, bool Require, bool Global);

public sealed class SetApprovalSettingHandler(
    IApprovalSettingRepository settings,
    IRoleChangeRepository changes,
    IUnitOfWork unitOfWork,
    ManagementGuard guard,
    ManagementAudit audit,
    TimeProvider time) : ICommandHandler<SetApprovalSettingCommand, ChangeOutcomeDto>
{
    public async Task<Result<ChangeOutcomeDto>> HandleAsync(SetApprovalSettingCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var caller = command.Caller;

        if (command.Global && !caller.IsRoot)
        {
            return Error.Forbidden(ManagementErrors.MissingPermission, "Only a platform administrator can change the global setting.");
        }

        Guid? tenantId = command.Global ? null : caller.EffectiveTenantId;
        if (!command.Global)
        {
            if (tenantId is null)
            {
                return Error.Forbidden(ManagementErrors.NotYourTenant, "Your session acts in no tenant.");
            }

            if (await guard.RequireAsync(caller, tenantId.Value, guard.Options.Permissions.RolesWrite, cancellationToken).ConfigureAwait(false) is { } refused)
            {
                return refused;
            }
        }

        var now = time.GetUtcNow();
        if (!command.Require && !caller.IsRoot && await guard.ApprovalRequiredAsync(tenantId, cancellationToken).ConfigureAwait(false))
        {
            var request = RoleChangeRequest.DisableApproval(tenantId, caller.UserId!.Value, now);
            changes.Add(request);
            await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            await audit.WriteAsync("approval.disable.requested", "approval_setting", tenantId?.ToString() ?? "global", caller, tenantId, cancellationToken).ConfigureAwait(false);
            return new ChangeOutcomeDto(Applied: false, request.Id);
        }

        var setting = await settings.GetAsync(tenantId, cancellationToken).ConfigureAwait(false);
        if (setting is null)
        {
            settings.Add(ApprovalSetting.Create(tenantId, command.Require, caller.UserId, now));
        }
        else
        {
            setting.Set(command.Require, caller.UserId, now);
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(command.Require ? "approval.enabled" : "approval.disabled", "approval_setting", tenantId?.ToString() ?? "global", caller, tenantId, cancellationToken).ConfigureAwait(false);
        return new ChangeOutcomeDto(Applied: true, null);
    }
}

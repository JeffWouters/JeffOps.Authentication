using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Domain.Management;
using JeffOps.Authorization.Domain.Permissions;
using Microsoft.Extensions.Options;

namespace JeffOps.Authorization.Application.Management;

/// <summary>
/// Checks shared by the management slices: acting in the right tenant, holding the permission (straight from the store), and
/// whether a change needs a second approver.
/// </summary>
public sealed class ManagementGuard(
    HeldPermissions held,
    IApprovalSettingRepository settings,
    IOptions<ManagementOptions> options)
{
    public ManagementOptions Options => options.Value;

    /// <summary>Fails unless <paramref name="caller"/> holds <paramref name="permission"/> in <paramref name="tenantId"/>.</summary>
    public async Task<Error?> RequireAsync(ManagementCaller caller, Guid tenantId, string permission, CancellationToken cancellationToken, string scopeKey = "tenant", Guid? instanceId = null)
    {
        ArgumentNullException.ThrowIfNull(caller);

        if (caller.IsRoot)
        {
            return null;
        }

        if (!caller.MayActIn(tenantId))
        {
            return Error.Forbidden(ManagementErrors.NotYourTenant, "You can only administer the tenant your session acts in.");
        }

        var holds = await held.OfCallerAsync(caller, tenantId, scopeKey, instanceId, cancellationToken).ConfigureAwait(false);
        return Permission.GrantsAny(holds, permission)
            ? null
            : Error.Forbidden(ManagementErrors.MissingPermission, $"You don't hold {permission} in this tenant.");
    }

    /// <summary>Whether role changes in <paramref name="tenantId"/> need four-eyes approval (tenant ?? global ?? required).</summary>
    public async Task<bool> ApprovalRequiredAsync(Guid? tenantId, CancellationToken cancellationToken)
    {
        var tenant = tenantId is { } id ? await settings.GetAsync(id, cancellationToken).ConfigureAwait(false) : null;
        var global = await settings.GetAsync(null, cancellationToken).ConfigureAwait(false);
        return ApprovalSetting.Effective(tenant, global);
    }
}

/// <summary>Applies role changes, directly or once approved, so both paths run the same checks.</summary>
public sealed class RoleChangeApplier(
    IRoleRepository roles,
    IAssignmentRepository assignments,
    IApprovalSettingRepository settings,
    HeldPermissions held,
    IOptions<ManagementOptions> options,
    TimeProvider time)
{
    /// <summary>Applies an approved (or not approval-gated) request. <paramref name="actor"/> is who makes it take effect.</summary>
    public async Task<Error?> ApplyAsync(RoleChangeRequest request, Guid actor, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        switch (request.Kind)
        {
            case RoleChangeKind.AddPermission or RoleChangeKind.RemovePermission:
                var role = await roles.FindAsync(request.RoleId!.Value, cancellationToken).ConfigureAwait(false);
                if (role is null)
                {
                    return Error.NotFound(ManagementErrors.NotFound, "The role no longer exists.");
                }

                _ = request.Kind == RoleChangeKind.AddPermission ? role.AddPermission(request.PermissionCode!) : role.RemovePermission(request.PermissionCode!);
                return null;

            case RoleChangeKind.DisableApproval:
                var setting = await settings.GetAsync(request.TenantId, cancellationToken).ConfigureAwait(false);
                if (setting is null)
                {
                    settings.Add(ApprovalSetting.Create(request.TenantId, requireApproval: false, actor, time.GetUtcNow()));
                }
                else
                {
                    setting.Set(false, actor, time.GetUtcNow());
                }

                return null;

            case RoleChangeKind.AssignRole:
                return await AssignAsync(request, actor, cancellationToken).ConfigureAwait(false);

            default:
                return Error.Failure("unsupported_change", "This kind of change can't be applied.");
        }
    }

    private async Task<Error?> AssignAsync(RoleChangeRequest request, Guid actor, CancellationToken cancellationToken)
    {
        var role = await roles.FindAsync(request.RoleId!.Value, cancellationToken).ConfigureAwait(false);
        if (role is null)
        {
            return Error.NotFound(ManagementErrors.NotFound, "The role no longer exists.");
        }

        var now = time.GetUtcNow();
        if (AssignmentRules.ExpiryProblem(role, request.ExpiresAt, now, options.Value.BreakGlassMaxDuration) is { } problem)
        {
            return Error.Failure(ManagementErrors.InvalidExpiry, problem);
        }

        var assignment = Assignment.Grant(request.TargetUserId!.Value, role.Id, request.TenantId!.Value, request.ScopeKey!, request.ScopeInstanceId, request.ExpiresAt, actor, now);
        assignments.Add(assignment);
        if (role.IsBreakGlass)
        {
            assignment.AnnouncePrivileged(role.Name, await WatchersAsync(request.TenantId.Value, cancellationToken).ConfigureAwait(false));
        }

        return null;
    }

    /// <summary>Who should hear about a privileged grant: everyone who administers assignments in the tenant.</summary>
    public async Task<IReadOnlyList<Guid>> WatchersAsync(Guid tenantId, CancellationToken cancellationToken)
    {
        var watchers = new List<Guid>();
        foreach (var userId in (await assignments.ListForTenantAsync(tenantId, cancellationToken).ConfigureAwait(false)).Select(assignment => assignment.UserId).Distinct())
        {
            var holds = await held.OfAsync(userId, tenantId, "tenant", null, cancellationToken).ConfigureAwait(false);
            if (Permission.GrantsAny(holds, options.Value.Permissions.AssignmentsWrite))
            {
                watchers.Add(userId);
            }
        }

        return watchers;
    }
}

/// <summary>Writes audit records for management actions.</summary>
public sealed class ManagementAudit(IAuditSink sink, TimeProvider time)
{
    public Task WriteAsync(string action, string targetType, string targetId, ManagementCaller caller, Guid? tenantId, CancellationToken cancellationToken, AuditSeverity severity = AuditSeverity.Information, IReadOnlyDictionary<string, string?>? details = null)
    {
        ArgumentNullException.ThrowIfNull(caller);

        return sink.WriteAsync(
            new AuditRecord(action, targetType, targetId)
            {
                ActorId = caller.UserId,
                TenantId = tenantId,
                OccurredAt = time.GetUtcNow(),
                Severity = severity,
                Details = details ?? new Dictionary<string, string?>(),
            },
            cancellationToken);
    }
}

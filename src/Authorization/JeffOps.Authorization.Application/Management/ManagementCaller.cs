using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Domain.Permissions;
using JeffOps.Authorization.Domain.Scopes;

namespace JeffOps.Authorization.Application.Management;

/// <summary>
/// Who is calling a management operation, read from their token by the endpoint. Management operations act in the caller's
/// effective tenant only (a delegated session in the tenant it acts in), unless the caller is Root.
/// </summary>
public sealed record ManagementCaller(Guid? UserId, bool IsRoot, bool IsService, string? ServiceName, Guid? TenantId, Guid? ActingTenantId)
{
    /// <summary>The caller's permission ceiling (a PAT), intersected with what they hold.</summary>
    public IReadOnlyList<string> PatCeiling { get; init; } = [];

    /// <summary>Permissions a service principal holds through its token.</summary>
    public IReadOnlyList<string> ServicePermissions { get; init; } = [];

    public Guid? EffectiveTenantId => ActingTenantId ?? TenantId;

    /// <summary>Whether the caller may act in <paramref name="tenantId"/> at all.</summary>
    public bool MayActIn(Guid tenantId) => IsRoot || (UserId is not null && EffectiveTenantId == tenantId);
}

/// <summary>
/// What a user holds in a tenant, read straight from the store (not the cache): the basis of the escalation checks, which
/// must never decide on stale data.
/// </summary>
public sealed class HeldPermissions(IAuthorizationReads reads, TimeProvider time)
{
    public async Task<IReadOnlyList<string>> OfAsync(Guid userId, Guid tenantId, string scopeKey, Guid? instanceId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var tree = await TreeAsync(cancellationToken).ConfigureAwait(false);
        var applicable = (await reads.AssignmentsOfAsync(userId, tenantId, cancellationToken).ConfigureAwait(false))
            .Where(assignment => !Domain.Assignments.AssignmentExpiry.IsExpired(assignment.ExpiresAt, now)
                && tree.IsWithin(scopeKey, assignment.ScopeKey)
                && (assignment.ScopeInstanceId is null || assignment.ScopeInstanceId == instanceId))
            .ToList();
        if (applicable.Count == 0)
        {
            return [];
        }

        // Every role the assignments name, in one read.
        var permissions = await reads.RolePermissionsAsync([.. applicable.Select(assignment => assignment.RoleId).Distinct()], cancellationToken).ConfigureAwait(false);
        return [.. applicable.SelectMany(assignment => permissions.TryGetValue(assignment.RoleId, out var codes) ? codes : [])];
    }

    /// <summary>What the caller may exercise: their holdings, cut down by their PAT ceiling. Root holds everything.</summary>
    public async Task<IReadOnlyList<string>> OfCallerAsync(ManagementCaller caller, Guid tenantId, string scopeKey, Guid? instanceId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(caller);

        IReadOnlyList<string> held = caller.IsRoot
            ? [Permission.Wildcard]
            : caller.UserId is { } user ? await OfAsync(user, tenantId, scopeKey, instanceId, cancellationToken).ConfigureAwait(false) : caller.ServicePermissions;

        if (caller.PatCeiling.Count == 0)
        {
            return held;
        }

        var ceiling = PermissionSet.From(caller.PatCeiling);
        var heldSet = PermissionSet.From(held);
        return [.. caller.PatCeiling.Where(heldSet.Grants), .. held.Where(ceiling.Grants)];
    }

    public async Task<ScopeTree> TreeAsync(CancellationToken cancellationToken) =>
        new((await reads.ScopesAsync(cancellationToken).ConfigureAwait(false)).Select(scope => KeyValuePair.Create(scope.Id, scope.ParentKey)));
}

/// <summary>Stable error codes of management refusals.</summary>
public static class ManagementErrors
{
    public const string NotFound = "not_found";
    public const string NotYourTenant = "not_your_tenant";
    public const string MissingPermission = "missing_permission";
    public const string Escalation = "privilege_escalation";
    public const string BuiltIn = "built_in";
    public const string UnknownPermission = "unknown_permission";
    public const string InvalidScope = "invalid_scope";
    public const string InvalidExpiry = "invalid_expiry";
    public const string SelfDecision = "self_decision";
    public const string AlreadyDecided = "already_decided";
    public const string SelfRecertification = "self_recertification";
    public const string InvalidCondition = "invalid_condition";
    public const string ScopeInUse = "scope_in_use";
    public const string Cycle = "scope_cycle";
    public const string Duplicate = "duplicate";
    public const string RegistrationDomain = "registration_domain";
}

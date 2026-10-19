using JeffOps.Authorization.Domain.Ceilings;
using JeffOps.Authorization.Domain.Scopes;

namespace JeffOps.Authorization.AspNetCore;

/// <summary>
/// Options of permission-based authorization in a resource service. Bound from <see cref="SectionName"/>.
/// The product-specific lists (sensitive permissions, impersonation-refused permissions, delegation scopes) live here
/// rather than in code, so each product declares its own (docs/DESIGN.md §11.3).
/// </summary>
public sealed class PermissionAuthorizationOptions
{
    /// <summary>The configuration section the options bind from: <c>JeffOps:Authorization</c>.</summary>
    public const string SectionName = "JeffOps:Authorization";

    /// <summary>Base address of the authorization management service whose read API is cached locally.</summary>
    public Uri? ManagementBaseAddress { get; set; }

    /// <summary>The scope a permission check targets when the endpoint names none.</summary>
    public string DefaultScopeKey { get; set; } = WellKnownScopes.Tenant;

    /// <summary>Permissions that need a stepped-up (multi-factor) sign-in for interactive users.</summary>
    public IList<string> SensitivePermissions { get; } = [];

    /// <summary>
    /// Permissions an impersonation session may not use on state-changing requests: those that hand out or withdraw
    /// access, or change where tenant data is delivered. Empty by default, and the host warns at startup while it is.
    /// </summary>
    public IList<string> ImpersonationRefusedPermissions { get; } = [];

    /// <summary>
    /// Permissions Root does not hold just by being Root: a Root caller needs a role grant for them like anyone else, so
    /// holding one is a decision someone made. Default: <c>auth.impersonation.breakglass</c>.
    /// </summary>
    public IList<string> ExplicitGrantPermissions { get; } = ["auth.impersonation.breakglass"];

    /// <summary>The scopes a delegated (impersonation or tenant-switch) token can carry, and what each one allows.</summary>
    public DelegationCeilingOptions Delegation { get; } = new();

    /// <summary>Lifetimes, sealing key and partition of the local decision cache.</summary>
    public DecisionCacheOptions Cache { get; } = new();

    internal DelegationCeiling BuildDelegationCeiling() => new(
        [.. Delegation.UnrestrictedScopes],
        Delegation.VerbScopes.ToDictionary(
            pair => pair.Key, pair => (IReadOnlyCollection<string>)[.. pair.Value], StringComparer.OrdinalIgnoreCase),
        Delegation.PrefixScopes.ToDictionary(
            pair => pair.Key, pair => (IReadOnlyCollection<string>)[.. pair.Value], StringComparer.OrdinalIgnoreCase));
}

/// <summary>The scopes a delegated session can carry, and what each one allows. See <see cref="DelegationCeiling"/>.</summary>
public sealed class DelegationCeilingOptions
{
    /// <summary>Scopes that lift the ceiling. Default: <c>admin</c>.</summary>
    public IList<string> UnrestrictedScopes { get; } = ["admin"];

    /// <summary>Scopes limited to actions ending in one of the verbs. Default: <c>readonly</c> → <c>read</c>.</summary>
    public IDictionary<string, List<string>> VerbScopes { get; } =
        new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase) { ["readonly"] = ["read"] };

    /// <summary>Scopes limited to actions with one of the prefixes, e.g. <c>billing</c> → <c>billing.</c>.</summary>
    public IDictionary<string, List<string>> PrefixScopes { get; } =
        new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// The local decision cache. Entries are sealed with HMAC-SHA256 so a value planted in a shared distributed cache by another
/// workload is rejected instead of authorizing anything.
/// </summary>
public sealed class DecisionCacheOptions
{
    /// <summary>How long a user's role assignments are cached; also the revocation window without invalidation events.</summary>
    public TimeSpan Assignments { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>How long the permissions of each role are cached. Default: 10 minutes.</summary>
    public TimeSpan RolePermissions { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>How long the attribute policies are cached. Default: 60 seconds.</summary>
    public TimeSpan Policies { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>How long the scope hierarchy is cached. Default: 5 minutes.</summary>
    public TimeSpan Scopes { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>How long past its lifetime a sealed entry is still accepted, to ride out a short outage of the source.</summary>
    public TimeSpan MaxStale { get; set; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// The secret entries are sealed with. Replicas of one service must share it to share distributed-cache entries.
    /// When unset, a random per-process key is used: safe, but replicas then can't reuse each other's entries.
    /// </summary>
    public string? SealingKey { get; set; }

    /// <summary>Partitions cache keys, so services sharing a distributed cache never read each other's entries.</summary>
    public string Partition { get; set; } = "default";
}

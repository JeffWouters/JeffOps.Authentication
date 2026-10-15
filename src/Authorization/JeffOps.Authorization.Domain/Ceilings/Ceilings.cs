using JeffOps.Authorization.Domain.Permissions;

namespace JeffOps.Authorization.Domain.Ceilings;

/// <summary>
/// The permission ceiling a personal access token carries: the most the token may do, whatever its owner may do.
/// Subtractive only — it is intersected with the decision, never a source of authority — so an over-broad ceiling grants
/// nothing. An empty ceiling means unrestricted (tokens that carry none).
/// </summary>
public static class PatCeiling
{
    public static bool Allows(IReadOnlyCollection<string> ceiling, string action)
    {
        ArgumentNullException.ThrowIfNull(ceiling);
        return ceiling.Count == 0 || Permission.GrantsAny(ceiling, action);
    }

    /// <summary>Splits a stored, space-delimited ceiling into permission codes.</summary>
    public static IReadOnlyList<string> Parse(string? stored) =>
        string.IsNullOrWhiteSpace(stored)
            ? []
            : stored.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

/// <summary>
/// The ceiling a delegation's scope puts on a delegated (tenant-switch) session. Subtractive only. A session carrying no
/// scope values is unrestricted; several values form a union; a value the ceiling doesn't know grants nothing.
/// </summary>
/// <param name="UnrestrictedScopes">Scopes that lift the ceiling entirely (still bounded by RBAC). Default: <c>admin</c>.</param>
/// <param name="VerbScopes">Scopes limited to actions whose last segment is one of the listed verbs. Default: <c>readonly</c> → <c>read</c>.</param>
/// <param name="PrefixScopes">Scopes limited to actions starting with one of the listed prefixes, e.g. <c>billing</c> → <c>billing.</c>.</param>
public sealed record DelegationCeiling(
    IReadOnlyCollection<string> UnrestrictedScopes,
    IReadOnlyDictionary<string, IReadOnlyCollection<string>> VerbScopes,
    IReadOnlyDictionary<string, IReadOnlyCollection<string>> PrefixScopes)
{
    public static DelegationCeiling Default { get; } = new(
        ["admin"],
        new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.OrdinalIgnoreCase) { ["readonly"] = ["read"] },
        new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.OrdinalIgnoreCase));

    public bool Allows(IReadOnlyCollection<string> scopes, string action)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(action);

        if (scopes.Count == 0)
        {
            return true;
        }

        var normalized = Permission.Normalize(action);
        var lastDot = normalized.LastIndexOf('.');
        var verb = lastDot > 0 ? normalized[(lastDot + 1)..] : null;

        foreach (var raw in scopes)
        {
            var scope = raw.Trim();
            if (UnrestrictedScopes.Contains(scope, StringComparer.OrdinalIgnoreCase))
            {
                return true;
            }

            if (verb is not null
                && VerbScopes.TryGetValue(scope, out var verbs)
                && verbs.Contains(verb, StringComparer.OrdinalIgnoreCase))
            {
                return true;
            }

            if (PrefixScopes.TryGetValue(scope, out var prefixes)
                && prefixes.Any(prefix => normalized.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>
/// Route metadata adjusting step-up for one endpoint. A requirement adds step-up to the route (for the named permissions, or
/// all permissions it checks when none are named); an exemption lifts it for the named sensitive permissions only.
/// </summary>
public sealed class StepUpRouteRule
{
    private StepUpRouteRule(bool required, IReadOnlyList<string> permissions)
    {
        Required = required;
        Permissions = permissions;
    }

    public bool Required { get; }

    /// <summary>Covered permissions; empty (requirements only) covers every permission checked on the route.</summary>
    public IReadOnlyList<string> Permissions { get; }

    public static StepUpRouteRule Require(params string[] permissions) => new(true, Normalize(permissions));

    /// <summary>
    /// Lifts step-up for the named permissions on one route. Each must be a sensitive permission; that is validated when
    /// the host starts (an exemption of a non-sensitive permission does nothing, so it can only be a typo or a stale rename).
    /// </summary>
    /// <exception cref="ArgumentException">No permission is named.</exception>
    public static StepUpRouteRule Exempt(params string[] permissions)
    {
        var normalized = Normalize(permissions);
        return normalized.Length == 0
            ? throw new ArgumentException("A step-up exemption must name the permissions it exempts.", nameof(permissions))
            : new StepUpRouteRule(false, normalized);
    }

    public bool Covers(string action) =>
        Permissions.Count == 0 || Permissions.Contains(action.Trim(), StringComparer.OrdinalIgnoreCase);

    private static string[] Normalize(string[]? permissions) =>
        [.. (permissions ?? []).Where(permission => !string.IsNullOrWhiteSpace(permission)).Select(permission => permission.Trim())];
}

/// <summary>
/// Step-up for sensitive actions: an interactive user must have signed in with strong authentication (the step-up claim)
/// to perform a sensitive permission. Subtractive only. Service principals are never asked for step-up.
/// </summary>
public sealed class StepUpPolicy(IReadOnlyCollection<string> sensitivePermissions)
{
    private readonly HashSet<string> _sensitive = new(sensitivePermissions.Select(Permission.Normalize), StringComparer.OrdinalIgnoreCase);

    public static StepUpPolicy None { get; } = new([]);

    public IReadOnlyCollection<string> SensitivePermissions => _sensitive;

    public bool IsSensitive(string action) => _sensitive.Contains(action.Trim());

    /// <summary>A rule requiring step-up wins; otherwise an exempting rule lifts it; otherwise the sensitive list decides.</summary>
    public bool IsRequired(string action, IReadOnlyCollection<StepUpRouteRule> routeRules)
    {
        ArgumentNullException.ThrowIfNull(routeRules);

        if (routeRules.Any(rule => rule.Required && rule.Covers(action)))
        {
            return true;
        }

        return IsSensitive(action) && !routeRules.Any(rule => !rule.Required && rule.Covers(action));
    }

    public bool Allows(string action, IReadOnlyCollection<StepUpRouteRule> routeRules, bool isInteractiveUser, bool stepUpSatisfied) =>
        !IsRequired(action, routeRules) || !isInteractiveUser || stepUpSatisfied;
}

/// <summary>
/// What an impersonation session may not do, even with the target's permissions: permissions that hand out or withdraw
/// access, or redirect where tenant data is delivered, so the actor can't turn consented support access into standing
/// access. Refused on state-changing requests (reads stay available), and every permission is refused on a route marked
/// to refuse impersonation. Subtractive only; never applies to tokens that are not impersonation tokens.
/// </summary>
public sealed class ImpersonationPolicy(IReadOnlyCollection<string> refusedPermissions)
{
    private readonly HashSet<string> _refused = new(refusedPermissions.Select(Permission.Normalize), StringComparer.OrdinalIgnoreCase);

    public static ImpersonationPolicy None { get; } = new([]);

    public IReadOnlyCollection<string> RefusedPermissions => _refused;

    public bool IsRefused(string action) => _refused.Contains(action.Trim());

    /// <param name="isImpersonation">Whether the caller's token is an impersonation token.</param>
    /// <param name="action">The permission being checked.</param>
    /// <param name="routeRefusesImpersonation">Whether the route is marked to refuse impersonation entirely.</param>
    /// <param name="isReadOnlyRequest">GET/HEAD. False when there is no request to judge: fail closed.</param>
    public bool Allows(bool isImpersonation, string action, bool routeRefusesImpersonation, bool isReadOnlyRequest) =>
        !isImpersonation || (!routeRefusesImpersonation && (isReadOnlyRequest || !IsRefused(action)));
}

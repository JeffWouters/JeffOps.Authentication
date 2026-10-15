using JeffOps.Authorization.Domain.Permissions;

namespace JeffOps.Authorization.Domain.Management;

/// <summary>
/// The rules that keep role administration from becoming privilege escalation (docs/DESIGN.md §11.5).
/// </summary>
public static class AssignmentRules
{
    /// <summary>
    /// Whether a role is privileged: a super-admin role, or one granting any of <paramref name="privilegedPermissions"/>
    /// (directly or through a wildcard).
    /// </summary>
    public static bool IsPrivileged(Role role, IReadOnlyCollection<string> privilegedPermissions)
    {
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(privilegedPermissions);

        var codes = role.PermissionCodes();
        return role.IsSuperAdmin || codes.Any(code => privilegedPermissions.Any(privileged => Permission.Grants(code, privileged)));
    }

    /// <summary>The permissions of <paramref name="required"/> that <paramref name="held"/> doesn't cover.</summary>
    public static IReadOnlyList<string> Uncovered(IReadOnlyCollection<string> held, IEnumerable<string> required)
    {
        ArgumentNullException.ThrowIfNull(held);
        ArgumentNullException.ThrowIfNull(required);

        var set = PermissionSet.From(held);
        return [.. required.Where(code => !set.Grants(code)).Distinct(StringComparer.OrdinalIgnoreCase)];
    }

    /// <summary>
    /// The privileged-role ceiling: to grant a privileged role, or any role to yourself, you must already hold every
    /// permission it carries. Returns the missing permissions; empty means allowed.
    /// </summary>
    public static IReadOnlyList<string> CeilingViolations(Role role, IReadOnlyCollection<string> granterHolds, bool grantingToSelf, IReadOnlyCollection<string> privilegedPermissions)
    {
        ArgumentNullException.ThrowIfNull(role);

        return grantingToSelf || IsPrivileged(role, privilegedPermissions)
            ? Uncovered(granterHolds, role.PermissionCodes())
            : [];
    }

    /// <summary>The problem with an assignment's expiry, or null. Break-glass roles must be time-boxed within the maximum.</summary>
    public static string? ExpiryProblem(Role role, DateTimeOffset? expiresAt, DateTimeOffset now, TimeSpan breakGlassMaxDuration)
    {
        ArgumentNullException.ThrowIfNull(role);

        if (expiresAt is { } requested && requested <= now)
        {
            return "The expiry must be in the future.";
        }

        if (!role.IsBreakGlass)
        {
            return null;
        }

        return expiresAt is not { } end
            ? $"'{role.Name}' can only be assigned time-boxed: set an expiry."
            : end - now > breakGlassMaxDuration ? $"'{role.Name}' can be assigned for at most {breakGlassMaxDuration}." : null;
    }

    /// <summary>The problem with a recertification, or null.</summary>
    public static string? RecertifyProblem(DateTimeOffset newExpiresAt, DateTimeOffset now, TimeSpan maxExtension) =>
        newExpiresAt <= now ? "The expiry must be in the future."
        : newExpiresAt - now > maxExtension ? $"An assignment can be recertified for at most {maxExtension} ahead."
        : null;

    /// <summary>Whether a role may be assigned at <paramref name="scopeKey"/>, given its minimum scope.</summary>
    public static bool ScopeAllowed(Role role, string scopeKey, Scopes.ScopeTree scopes)
    {
        ArgumentNullException.ThrowIfNull(role);
        ArgumentNullException.ThrowIfNull(scopes);

        // A role with a minimum scope may be assigned at that scope or above it (a broader scope contains the minimum).
        return scopes.Contains(scopeKey) && (role.MinScopeKey is null || scopes.IsWithin(role.MinScopeKey, scopeKey));
    }
}

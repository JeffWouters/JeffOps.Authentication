using JeffOps.Authorization.Domain.Permissions;
using JeffOps.Authorization.Domain.Scopes;

namespace JeffOps.Authorization.Domain.Assignments;

/// <summary>
/// A role assigned to a subject at a scope, optionally confined to one instance of that scope and optionally expiring.
/// </summary>
public sealed record RoleAssignment(Guid RoleId, string ScopeKey, Guid? ScopeInstanceId = null, DateTimeOffset? ExpiresAt = null);

/// <summary>
/// The single rule for whether a time-boxed grant is still effective. Runtime checks and the expiry sweeper both use it.
/// </summary>
public static class AssignmentExpiry
{
    public static bool IsExpired(DateTimeOffset? expiresAt, DateTimeOffset now) => expiresAt is { } end && end <= now;

    public static bool IsActive(DateTimeOffset? expiresAt, DateTimeOffset now) => !IsExpired(expiresAt, now);
}

/// <summary>
/// Role-based access: whether a subject's assignments grant a permission for a request at a scope.
/// </summary>
public static class RoleBasedAccess
{
    /// <summary>
    /// True when an active assignment's role grants <paramref name="permission"/>, the assignment's scope contains
    /// <paramref name="requestScopeKey"/>, and the assignment is either not confined to an instance or confined to
    /// <paramref name="requestInstanceId"/>.
    /// </summary>
    public static bool Grants(
        IEnumerable<RoleAssignment> assignments,
        IReadOnlyDictionary<Guid, PermissionSet> rolePermissions,
        ScopeTree scopes,
        string permission,
        string requestScopeKey,
        Guid? requestInstanceId,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(assignments);
        ArgumentNullException.ThrowIfNull(rolePermissions);
        ArgumentNullException.ThrowIfNull(scopes);

        foreach (var assignment in assignments)
        {
            if (AssignmentExpiry.IsExpired(assignment.ExpiresAt, now)
                || !rolePermissions.TryGetValue(assignment.RoleId, out var granted)
                || !granted.Grants(permission)
                || string.IsNullOrEmpty(assignment.ScopeKey)
                || !scopes.IsWithin(requestScopeKey, assignment.ScopeKey))
            {
                continue;
            }

            if (assignment.ScopeInstanceId is null || assignment.ScopeInstanceId == requestInstanceId)
            {
                return true;
            }
        }

        return false;
    }
}

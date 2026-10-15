namespace JeffOps.Authentication.Abstractions.Access;

/// <summary>
/// The breadth of tenant data a caller may reach. Ordered from narrowest to broadest, except <see cref="Service"/>,
/// which is off the ladder so any breadth comparison (<c>&gt;=</c>) fails closed for a service principal.
/// </summary>
public enum AccessLevel
{
    /// <summary>A service principal (client credentials). Authorized by its explicit permission grants, not by breadth.</summary>
    Service = -1,

    /// <summary>A single workspace inside the caller's own tenant.</summary>
    Workspace = 0,

    /// <summary>The caller's own tenant.</summary>
    Tenant = 1,

    /// <summary>All tenants owned by the caller's organization.</summary>
    Organization = 2,

    /// <summary>A managed tenant reached through a delegation.</summary>
    Delegated = 3,

    /// <summary>Platform administrator.</summary>
    Root = 4,
}

/// <summary>
/// The caller's tenancy context for the current request, derived from token claims without any network call.
/// </summary>
/// <param name="TenantId">The caller's home tenant.</param>
/// <param name="OrganizationId">The organization that owns the home tenant.</param>
/// <param name="WorkspaceId">The active workspace, if the session is workspace-scoped.</param>
/// <param name="UserId">The calling user; null for a service principal or an anonymous caller.</param>
/// <param name="Level">The resolved access level.</param>
/// <param name="ActingTenantId">The tenant being acted on in a delegated session; null for same-tenant calls.</param>
public sealed record AccessContext(
    Guid? TenantId,
    Guid? OrganizationId,
    Guid? WorkspaceId,
    Guid? UserId,
    AccessLevel Level,
    Guid? ActingTenantId = null)
{
    /// <summary>An unauthenticated caller with no tenant.</summary>
    public static AccessContext Anonymous { get; } = new(null, null, null, null, AccessLevel.Tenant);

    public bool IsRoot => Level == AccessLevel.Root;

    public bool IsService => Level == AccessLevel.Service;

    public bool IsDelegated => Level == AccessLevel.Delegated || ActingTenantId is not null;

    /// <summary>The tenant this request targets: the acting tenant in a delegated session, otherwise the home tenant.</summary>
    public Guid? EffectiveTenantId => ActingTenantId ?? TenantId;
}

/// <summary>
/// Provides the current request's <see cref="AccessContext"/>. Request-scoped and local.
/// </summary>
public interface IAccessContextAccessor
{
    AccessContext GetAccessContext();
}

public static class AccessContextAccessorExtensions
{
    /// <summary>The effective tenant of the current request, or throws when none is in scope.</summary>
    /// <exception cref="InvalidOperationException">No tenant is in scope.</exception>
    public static Guid RequireEffectiveTenant(this IAccessContextAccessor accessor)
    {
        ArgumentNullException.ThrowIfNull(accessor);
        return accessor.GetAccessContext().EffectiveTenantId
            ?? throw new InvalidOperationException("No tenant in scope.");
    }
}

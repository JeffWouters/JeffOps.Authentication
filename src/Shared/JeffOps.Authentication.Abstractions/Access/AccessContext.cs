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

    /// <summary>
    /// A managed tenant reached through a delegation, under the relationship's <c>dlg_scope</c> ceiling: one tenant's breadth,
    /// so below <see cref="Organization"/> (a partner switched into one customer tenant must not pass organization-wide checks).
    /// </summary>
    Delegated = 2,

    /// <summary>All tenants owned by the caller's organization.</summary>
    Organization = 3,

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

    /// <summary>Whether the caller is a platform administrator (<see cref="AccessLevel.Root"/>).</summary>
    public bool IsRoot => Level == AccessLevel.Root;

    /// <summary>Whether the caller is a service principal, which is authorized by its permission grants rather than by <see cref="Level"/>.</summary>
    public bool IsService => Level == AccessLevel.Service;

    /// <summary>Whether the caller is acting on a managed tenant: at <see cref="AccessLevel.Delegated"/> or with an <see cref="ActingTenantId"/>.</summary>
    public bool IsDelegated => Level == AccessLevel.Delegated || ActingTenantId is not null;

    /// <summary>The tenant this request targets: the acting tenant in a delegated session, otherwise the home tenant.</summary>
    public Guid? EffectiveTenantId => ActingTenantId ?? TenantId;
}

/// <summary>
/// Provides the current request's <see cref="AccessContext"/>. Request-scoped and local.
/// </summary>
public interface IAccessContextAccessor
{
    /// <summary>The current request's access context; <see cref="AccessContext.Anonymous"/> for an unauthenticated caller.</summary>
    AccessContext GetAccessContext();
}

/// <summary>Convenience methods over <see cref="IAccessContextAccessor"/>.</summary>
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

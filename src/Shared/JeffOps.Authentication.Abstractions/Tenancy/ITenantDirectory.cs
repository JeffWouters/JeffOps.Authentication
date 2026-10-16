using JeffOps.Authentication.Abstractions.Access;

namespace JeffOps.Authentication.Abstractions.Tenancy;

/// <summary>An account's membership of a tenant, as the host's tenant system reports it.</summary>
/// <param name="TenantId">The tenant.</param>
/// <param name="OrganizationId">The organization owning the tenant, if the host has organizations.</param>
/// <param name="WorkspaceId">The workspace the membership is limited to, if any.</param>
/// <param name="Level">The breadth of access the membership grants.</param>
public sealed record TenantMembership(Guid TenantId, Guid? OrganizationId, Guid? WorkspaceId, AccessLevel Level);

/// <summary>A tenant as the token server needs to know it.</summary>
/// <param name="TenantId">The tenant.</param>
/// <param name="OrganizationId">Its organization, if any.</param>
/// <param name="AcceptsSessions">False while the tenant is suspended, offboarding or deleted: no session may be issued for it.</param>
public sealed record TenantInfo(Guid TenantId, Guid? OrganizationId, bool AcceptsSessions);

/// <summary>
/// The host's tenant system, as the token server sees it (docs/DESIGN.md §13). Every session is issued and refreshed against
/// live answers from here, so removing a membership or suspending a tenant takes effect at the next refresh.
/// </summary>
/// <remarks>
/// Implementations throw when the tenant system can't answer; the token server then reports a server error so clients retry,
/// instead of treating the outage as a revoked session.
/// </remarks>
public interface ITenantDirectory
{
    /// <summary>The account's active memberships, most relevant first.</summary>
    Task<IReadOnlyList<TenantMembership>> GetMembershipsAsync(Guid accountId, CancellationToken cancellationToken);

    /// <summary>The tenant, or null when it doesn't exist.</summary>
    Task<TenantInfo?> FindTenantAsync(Guid tenantId, CancellationToken cancellationToken);
}

/// <summary>
/// The tenant directory of a single-tenant host: nobody has memberships, so tokens carry no tenant claims.
/// </summary>
public sealed class NoTenantDirectory : ITenantDirectory
{
    /// <summary>Always returns no memberships.</summary>
    public Task<IReadOnlyList<TenantMembership>> GetMembershipsAsync(Guid accountId, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<TenantMembership>>([]);

    /// <summary>Always returns null: a single-tenant host has no tenants.</summary>
    public Task<TenantInfo?> FindTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        Task.FromResult<TenantInfo?>(null);
}

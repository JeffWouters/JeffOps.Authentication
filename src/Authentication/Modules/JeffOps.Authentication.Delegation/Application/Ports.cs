using JeffOps.Authentication.Delegation.Domain;

namespace JeffOps.Authentication.Delegation.Application;

/// <summary>
/// The host's partner relationships (docs/DESIGN.md §12): which tenants an organization manages, with which delegation
/// scopes, and which tenants require approval (lockbox) for every partner session. Asked on every request and token mint,
/// so ending a relationship takes effect within one token lifetime.
/// </summary>
/// <remarks>Implementations throw when they can't answer; the token server then reports a server error so clients retry.</remarks>
public interface IDelegationDirectory
{
    /// <summary>
    /// The delegation scopes <paramref name="organizationId"/> holds over <paramref name="tenantId"/> (for example
    /// <c>admin</c>, <c>readonly</c>, <c>billing</c>), emitted as <c>dlg_scope</c> claims; empty when it doesn't manage it.
    /// </summary>
    Task<IReadOnlyList<string>> GetDelegationScopesAsync(Guid organizationId, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>Whether partner sessions into <paramref name="tenantId"/> need an approved tenant-access grant.</summary>
    Task<bool> RequiresAccessApprovalAsync(Guid tenantId, CancellationToken cancellationToken);
}

/// <summary>The default: no organization manages any tenant, so only platform staff can impersonate.</summary>
public sealed class NoDelegations : IDelegationDirectory
{
    public Task<IReadOnlyList<string>> GetDelegationScopesAsync(Guid organizationId, Guid tenantId, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<string>>([]);

    public Task<bool> RequiresAccessApprovalAsync(Guid tenantId, CancellationToken cancellationToken) => Task.FromResult(false);
}

public interface IImpersonationGrantRepository
{
    Task<ImpersonationGrant?> FindAsync(Guid grantId, CancellationToken cancellationToken);

    /// <summary>Grants naming the user as actor or target that are pending or live at <paramref name="now"/>.</summary>
    Task<IReadOnlyList<ImpersonationGrant>> ListOpenAsync(Guid userId, DateTimeOffset now, CancellationToken cancellationToken);

    void Add(ImpersonationGrant grant);
}

public interface ITenantAccessGrantRepository
{
    Task<TenantAccessGrant?> FindAsync(Guid grantId, CancellationToken cancellationToken);

    /// <summary>Grants of the actor or into the tenant that are pending or live at <paramref name="now"/>.</summary>
    Task<IReadOnlyList<TenantAccessGrant>> ListOpenAsync(Guid? actorUserId, Guid? tenantId, DateTimeOffset now, CancellationToken cancellationToken);

    void Add(TenantAccessGrant grant);
}

/// <summary>Grants whose approval deadline or session window has passed without a terminal status.</summary>
public interface IDueGrantSource
{
    Task<IReadOnlyList<DelegationGrant>> ListDueAsync(DateTimeOffset now, CancellationToken cancellationToken);
}

public interface IDelegationUnitOfWork
{
    /// <summary>Saves, then dispatches domain events. False when another request changed a grant first (nothing saved).</summary>
    Task<bool> TrySaveChangesAsync(CancellationToken cancellationToken);

    /// <summary>Discards local changes to <paramref name="grant"/> and reloads its committed state.</summary>
    Task ReloadAsync(DelegationGrant grant, CancellationToken cancellationToken);
}

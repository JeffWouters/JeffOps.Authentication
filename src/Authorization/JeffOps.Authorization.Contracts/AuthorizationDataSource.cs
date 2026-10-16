namespace JeffOps.Authorization.Contracts;

/// <summary>
/// Where a resource service reads the role and policy data it caches. The default reads the management service's HTTP API;
/// the management service itself registers one that reads its store directly (D13).
/// </summary>
public interface IAuthorizationDataSource
{
    /// <summary>Reads a user's role assignments in one tenant, including those inherited through groups.</summary>
    /// <param name="userId">The user whose assignments to read.</param>
    /// <param name="tenantId">The tenant the assignments apply in.</param>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The user's assignments in the tenant; empty when there are none.</returns>
    Task<IReadOnlyList<UserAssignmentDto>> GetUserAssignmentsAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken);

    /// <summary>Reads the permission codes granted by every role.</summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>A map of role id to the permission codes (possibly wildcards) the role grants.</returns>
    Task<IReadOnlyDictionary<Guid, string[]>> GetRolePermissionsAsync(CancellationToken cancellationToken);

    /// <summary>Reads every stored ABAC policy, enabled or not.</summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>The stored policies.</returns>
    Task<IReadOnlyList<AttributePolicyDto>> GetPoliciesAsync(CancellationToken cancellationToken);

    /// <summary>Reads the whole scope hierarchy.</summary>
    /// <param name="cancellationToken">Cancels the read.</param>
    /// <returns>Every scope node; the tree is rebuilt from <see cref="ScopeDto.ParentKey"/>.</returns>
    Task<IReadOnlyList<ScopeDto>> GetScopesAsync(CancellationToken cancellationToken);
}

/// <summary>Declares a service's permissions to the management service's registry.</summary>
public interface IPermissionRegistry
{
    /// <summary>
    /// Registers the service's complete permission set under its own name; codes it declared before but omits now are
    /// marked stale.
    /// </summary>
    /// <param name="request">The registering service and its permission definitions.</param>
    /// <param name="cancellationToken">Cancels the registration.</param>
    /// <returns>A task that completes when the registry has accepted the definitions.</returns>
    Task RegisterAsync(RegisterPermissionsRequest request, CancellationToken cancellationToken);
}


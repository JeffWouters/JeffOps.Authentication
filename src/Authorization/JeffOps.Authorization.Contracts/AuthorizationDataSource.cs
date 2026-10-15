namespace JeffOps.Authorization.Contracts;

/// <summary>
/// Where a resource service reads the role and policy data it caches. The default reads the management service's HTTP API;
/// the management service itself registers one that reads its store directly (D13).
/// </summary>
public interface IAuthorizationDataSource
{
    Task<IReadOnlyList<UserAssignmentDto>> GetUserAssignmentsAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken);

    Task<IReadOnlyDictionary<Guid, string[]>> GetRolePermissionsAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<AttributePolicyDto>> GetPoliciesAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<ScopeDto>> GetScopesAsync(CancellationToken cancellationToken);
}

/// <summary>Declares a service's permissions to the management service's registry.</summary>
public interface IPermissionRegistry
{
    Task RegisterAsync(RegisterPermissionsRequest request, CancellationToken cancellationToken);
}


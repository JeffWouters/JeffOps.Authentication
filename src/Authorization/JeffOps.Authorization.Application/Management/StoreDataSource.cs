using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Contracts;

namespace JeffOps.Authorization.Application.Management;

/// <summary>
/// The read API, straight from the store: what resource services cache to decide locally. The management service serves it
/// over HTTP and also uses it in-process to authorize its own endpoints (docs/DESIGN.md D13).
/// </summary>
public sealed class StoreDataSource(
    IAssignmentRepository assignments,
    IGroupAssignmentRepository groupAssignments,
    IRoleRepository roles,
    IPolicyRepository policies,
    IScopeRepository scopes)
    : IAuthorizationDataSource
{
    /// <summary>Direct assignments and those reaching the user through their groups.</summary>
    public async Task<IReadOnlyList<UserAssignmentDto>> GetUserAssignmentsAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken) =>
        [
            .. (await assignments.ListForUserAsync(userId, tenantId, cancellationToken).ConfigureAwait(false))
                .Select(assignment => new UserAssignmentDto(assignment.RoleId, assignment.ScopeKey, assignment.ScopeInstanceId, assignment.ExpiresAt)),
            .. (await groupAssignments.ListForUserAsync(userId, tenantId, cancellationToken).ConfigureAwait(false))
                .Select(assignment => new UserAssignmentDto(assignment.RoleId, assignment.ScopeKey, assignment.ScopeInstanceId, assignment.ExpiresAt)),
        ];

    public async Task<IReadOnlyDictionary<Guid, string[]>> GetRolePermissionsAsync(CancellationToken cancellationToken) =>
        (await roles.ListAllAsync(cancellationToken).ConfigureAwait(false)).ToDictionary(role => role.Id, role => role.PermissionCodes().ToArray());

    public async Task<IReadOnlyList<AttributePolicyDto>> GetPoliciesAsync(CancellationToken cancellationToken) =>
        [.. (await policies.ListAsync(cancellationToken).ConfigureAwait(false)).Select(policy => new AttributePolicyDto(
            policy.Id, policy.Name, policy.Description, policy.TargetAction, policy.TargetResourceType, policy.Effect, policy.ConditionJson, policy.Priority, policy.Enabled))];

    public async Task<IReadOnlyList<ScopeDto>> GetScopesAsync(CancellationToken cancellationToken) =>
        [.. (await scopes.ListAsync(cancellationToken).ConfigureAwait(false)).Select(scope => new ScopeDto(scope.Id, scope.Name, scope.Description, scope.ParentKey, scope.IsBuiltIn))];
}

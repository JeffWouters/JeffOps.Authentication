using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Assignments;
using JeffOps.Authorization.Domain.Permissions;
using JeffOps.Authorization.Domain.Policies;
using JeffOps.Authorization.Domain.Scopes;
using Microsoft.Extensions.Options;

namespace JeffOps.Authorization.AspNetCore.Data;

/// <summary>
/// The role and policy data authorization decisions are made from, already compiled for evaluation. Served from the sealed
/// local cache; a miss reads <see cref="IAuthorizationDataSource"/> once.
/// </summary>
public interface IAuthorizationData
{
    Task<IReadOnlyList<RoleAssignment>> GetAssignmentsAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken);

    Task<IReadOnlyDictionary<Guid, PermissionSet>> GetRolePermissionsAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<AttributePolicy>> GetPoliciesAsync(CancellationToken cancellationToken);

    Task<ScopeTree> GetScopesAsync(CancellationToken cancellationToken);
}

/// <summary>Cache keys, shared by the cache and its invalidation handlers.</summary>
internal static class AuthorizationCacheKeys
{
    public const string RolePermissions = "role-permissions";
    public const string Policies = "policies";
    public const string Scopes = "scopes";

    public static string Assignments(Guid userId, Guid tenantId) => $"assignments:{userId:N}:{tenantId:N}";
}

internal sealed class CachedAuthorizationData(
    SealedDecisionCache cache,
    IAuthorizationDataSource source,
    IOptions<PermissionAuthorizationOptions> options) : IAuthorizationData
{
    private DecisionCacheOptions Lifetimes => options.Value.Cache;

    public Task<IReadOnlyList<RoleAssignment>> GetAssignmentsAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken) =>
        cache.GetOrCreateAsync<UserAssignmentDto[], IReadOnlyList<RoleAssignment>>(
            AuthorizationCacheKeys.Assignments(userId, tenantId),
            async token => [.. await source.GetUserAssignmentsAsync(userId, tenantId, token).ConfigureAwait(false)],
            stored => [.. stored.Select(dto => new RoleAssignment(dto.RoleId, dto.ScopeKey, dto.ScopeInstanceId, dto.ExpiresAt))],
            Lifetimes.Assignments,
            cancellationToken);

    public Task<IReadOnlyDictionary<Guid, PermissionSet>> GetRolePermissionsAsync(CancellationToken cancellationToken) =>
        cache.GetOrCreateAsync<Dictionary<Guid, string[]>, IReadOnlyDictionary<Guid, PermissionSet>>(
            AuthorizationCacheKeys.RolePermissions,
            async token => new Dictionary<Guid, string[]>(await source.GetRolePermissionsAsync(token).ConfigureAwait(false)),
            stored => stored.ToDictionary(pair => pair.Key, pair => PermissionSet.From(pair.Value)),
            Lifetimes.RolePermissions,
            cancellationToken);

    public Task<IReadOnlyList<AttributePolicy>> GetPoliciesAsync(CancellationToken cancellationToken) =>
        cache.GetOrCreateAsync<AttributePolicyDto[], IReadOnlyList<AttributePolicy>>(
            AuthorizationCacheKeys.Policies,
            async token => [.. await source.GetPoliciesAsync(token).ConfigureAwait(false)],
            stored => [.. stored.Select(dto => AttributePolicy.Compile(
                dto.Name, dto.Effect, dto.TargetAction, dto.TargetResourceType, dto.ConditionJson, dto.Priority, dto.Enabled))],
            Lifetimes.Policies,
            cancellationToken);

    public Task<ScopeTree> GetScopesAsync(CancellationToken cancellationToken) =>
        cache.GetOrCreateAsync<ScopeDto[], ScopeTree>(
            AuthorizationCacheKeys.Scopes,
            async token => [.. await source.GetScopesAsync(token).ConfigureAwait(false)],
            stored => new ScopeTree(stored.Select(scope => KeyValuePair.Create(scope.Key, scope.ParentKey))),
            Lifetimes.Scopes,
            cancellationToken);
}

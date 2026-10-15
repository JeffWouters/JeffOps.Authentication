using JeffOps.Authorization.Domain.Permissions;
using JeffOps.Authorization.Domain.Policies;

namespace JeffOps.Authorization.Contracts;

/// <summary>
/// Routes of the authorization read API that resource services cache from, relative to the management service's base
/// address. Shared by <c>JeffOps.Authorization.Endpoints</c> (which maps them) and <c>JeffOps.Authorization.AspNetCore</c>
/// (which calls them), so the two cannot drift.
/// </summary>
public static class AuthorizationRoutes
{
    public const string UserAssignments = "authorization/users/{userId}/tenants/{tenantId}/assignments";
    public const string RolePermissions = "authorization/role-permissions";
    public const string Policies = "authorization/policies";
    public const string Scopes = "authorization/scopes";
    public const string RegisterPermissions = "authorization/permissions/register";

    public static string UserAssignmentsOf(Guid userId, Guid tenantId) => $"authorization/users/{userId}/tenants/{tenantId}/assignments";
}

/// <summary>A role assignment as resource services see it.</summary>
public sealed record UserAssignmentDto(Guid RoleId, string ScopeKey, Guid? ScopeInstanceId, DateTimeOffset? ExpiresAt);

/// <summary>A stored ABAC policy. <see cref="ConditionJson"/> uses the grammar of <see cref="ConditionParser"/>.</summary>
public sealed record AttributePolicyDto(
    Guid Id,
    string Name,
    string? Description,
    string TargetAction,
    string? TargetResourceType,
    PolicyEffect Effect,
    string ConditionJson,
    int Priority,
    bool Enabled);

/// <summary>A node of the scope hierarchy. <see cref="ParentKey"/> is null only for the root.</summary>
public sealed record ScopeDto(string Key, string Name, string? Description, string? ParentKey, bool IsBuiltIn);

/// <summary>A service's declared permissions, pushed to the registry at startup.</summary>
public sealed record RegisterPermissionsRequest(string Source, IReadOnlyList<PermissionDefinition> Definitions);

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
    /// <summary>
    /// Route template (<c>GET</c>) for a user's role assignments in one tenant, with <c>{userId}</c> and <c>{tenantId}</c>
    /// placeholders. Use <see cref="UserAssignmentsOf"/> to build a concrete path.
    /// </summary>
    public const string UserAssignments = "authorization/users/{userId}/tenants/{tenantId}/assignments";

    /// <summary>Route (<c>GET</c>) for the map of every role id to the permission codes it grants.</summary>
    public const string RolePermissions = "authorization/role-permissions";

    /// <summary>Route (<c>GET</c>) for the stored ABAC policies, as <see cref="AttributePolicyDto"/>.</summary>
    public const string Policies = "authorization/policies";

    /// <summary>Route (<c>GET</c>) for the scope hierarchy, as <see cref="ScopeDto"/>.</summary>
    public const string Scopes = "authorization/scopes";

    /// <summary>
    /// Route (<c>POST</c>) where a service registers its declared permissions with a
    /// <see cref="RegisterPermissionsRequest"/>; the caller needs <c>authorization.permissions.register</c>.
    /// </summary>
    public const string RegisterPermissions = "authorization/permissions/register";

    /// <summary>Builds the concrete <see cref="UserAssignments"/> path for one user in one tenant.</summary>
    /// <param name="userId">The user whose assignments to read.</param>
    /// <param name="tenantId">The tenant the assignments apply in.</param>
    /// <returns>The relative path, e.g. <c>authorization/users/{guid}/tenants/{guid}/assignments</c>.</returns>
    public static string UserAssignmentsOf(Guid userId, Guid tenantId) => $"authorization/users/{userId}/tenants/{tenantId}/assignments";
}

/// <summary>A role assignment as resource services see it.</summary>
/// <param name="RoleId">The assigned role.</param>
/// <param name="ScopeKey">The scope level the role applies at, e.g. <c>tenant</c> or <c>workspace</c>.</param>
/// <param name="ScopeInstanceId">The specific scope instance (e.g. a workspace id); null when the scope has no instance, such as <c>tenant</c>.</param>
/// <param name="ExpiresAt">When the assignment stops granting access; null when it does not expire.</param>
public sealed record UserAssignmentDto(Guid RoleId, string ScopeKey, Guid? ScopeInstanceId, DateTimeOffset? ExpiresAt);

/// <summary>A stored ABAC policy. <see cref="ConditionJson"/> uses the grammar of <see cref="ConditionParser"/>.</summary>
/// <param name="Id">The policy's identifier.</param>
/// <param name="Name">The policy's name, shown in decision traces.</param>
/// <param name="Description">An optional explanation for administrators.</param>
/// <param name="TargetAction">The permission the policy applies to: an exact code or <c>*</c> for any.</param>
/// <param name="TargetResourceType">The resource type the policy is limited to; null or <c>*</c> means any.</param>
/// <param name="Effect">Whether a match permits or denies; a matching Deny always wins.</param>
/// <param name="ConditionJson">The JSON condition tree evaluated against the request's attributes.</param>
/// <param name="Priority">Evaluation order; higher priorities are evaluated first.</param>
/// <param name="Enabled">False to keep the policy stored without evaluating it.</param>
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
/// <param name="Key">The scope's stable, lower-case key, e.g. <c>tenant</c>; used in assignments and permission checks.</param>
/// <param name="Name">The display name.</param>
/// <param name="Description">An optional explanation for administrators.</param>
/// <param name="ParentKey">The key of the enclosing (broader) scope; null for the root.</param>
/// <param name="IsBuiltIn">True for scopes seeded by the host, which can't be changed or deleted.</param>
public sealed record ScopeDto(string Key, string Name, string? Description, string? ParentKey, bool IsBuiltIn);

/// <summary>A service's declared permissions, pushed to the registry at startup.</summary>
/// <param name="Source">The registering service's name, e.g. <c>svc-billing</c>; it may only register codes in its own domain(s).</param>
/// <param name="Definitions">
/// The complete set the service declares now; previously registered codes missing from it are marked stale.
/// </param>
public sealed record RegisterPermissionsRequest(string Source, IReadOnlyList<PermissionDefinition> Definitions);

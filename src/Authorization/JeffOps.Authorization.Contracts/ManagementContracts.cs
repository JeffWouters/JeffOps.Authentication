using JeffOps.Authorization.Domain.Permissions;
using JeffOps.Authorization.Domain.Policies;

namespace JeffOps.Authorization.Contracts;

/// <summary>Routes of the management API (administrators), relative to the management service.</summary>
public static class ManagementRoutes
{
    /// <summary>The common prefix of every management route, <c>authorization/admin</c>.</summary>
    public const string Prefix = "authorization/admin";

    /// <summary>Route group for listing and creating roles and adding or removing a role's permissions.</summary>
    public const string Roles = Prefix + "/roles";

    /// <summary>Route group for the four-eyes queue: listing pending changes and approving or rejecting them.</summary>
    public const string RoleChanges = Prefix + "/role-changes";

    /// <summary>Route for reading and setting whether four-eyes approval is required, per tenant or globally.</summary>
    public const string ApprovalSetting = Prefix + "/approval-setting";

    /// <summary>Route group for granting, revoking and recertifying users' role assignments.</summary>
    public const string Assignments = Prefix + "/assignments";

    /// <summary>Route group for granting and revoking roles held by tenant groups.</summary>
    public const string GroupAssignments = Prefix + "/group-assignments";

    /// <summary>Route group for managing ABAC policies and simulating decisions (platform administrators only).</summary>
    public const string Policies = Prefix + "/policies";

    /// <summary>Route group for managing the scope hierarchy (platform administrators only).</summary>
    public const string Scopes = Prefix + "/scopes";

    /// <summary>Route for reading the permission catalog, as <see cref="CatalogEntryDto"/>.</summary>
    public const string Catalog = Prefix + "/permissions";
}

/// <summary>A role as administrators see it: a named bundle of permissions, built-in or custom.</summary>
/// <param name="Id">The role's identifier.</param>
/// <param name="Name">The role's name.</param>
/// <param name="TenantId">The tenant owning a custom role; null for global (built-in or platform-created) roles.</param>
/// <param name="IsBuiltIn">True for roles supplied by the host's role provider, which tenant administrators can't edit.</param>
/// <param name="IsSuperAdmin">True when the role implies every permission (<c>*</c>).</param>
/// <param name="IsBreakGlass">
/// True for emergency-access roles, which can only be assigned time-boxed and, for non-Root granters, after a second approval.
/// </param>
/// <param name="MinScopeKey">The narrowest scope the role may be assigned at; null when any scope is allowed.</param>
/// <param name="ComplianceControls">The compliance controls the role satisfies, e.g. <c>SOC2:CC6.1</c>.</param>
/// <param name="Permissions">The permission codes the role grants, in ordinal order.</param>
public sealed record RoleDto(
    Guid Id,
    string Name,
    Guid? TenantId,
    bool IsBuiltIn,
    bool IsSuperAdmin,
    bool IsBreakGlass,
    string? MinScopeKey,
    IReadOnlyList<string> ComplianceControls,
    IReadOnlyList<string> Permissions);

/// <summary>Creates a custom role in the caller's tenant, or a global role when a platform administrator asks.</summary>
/// <param name="Name">The role's name; required.</param>
/// <param name="Permissions">
/// The initial permission codes; each must be in the catalog and, unless the caller is Root, held by the caller.
/// </param>
/// <param name="MinScopeKey">The narrowest scope the role may be assigned at; null allows any scope.</param>
/// <param name="ComplianceControls">The compliance controls the role satisfies, e.g. <c>SOC2:CC6.1</c>.</param>
/// <param name="Global">True to create a global role instead of a tenant role; platform administrators only.</param>
public sealed record CreateRoleRequest(string Name, IReadOnlyList<string>? Permissions = null, string? MinScopeKey = null, IReadOnlyList<string>? ComplianceControls = null, bool Global = false);

/// <summary>Adds a permission to a role; may be queued for a second approver when four-eyes applies.</summary>
/// <param name="Permission">The permission code (or wildcard) to add; it must be in the catalog.</param>
public sealed record RolePermissionRequest(string Permission);

/// <summary>The outcome of a role or assignment change that may wait for a second approver.</summary>
/// <param name="Applied">True when applied now; false when queued for approval.</param>
/// <param name="RequestId">The approval request, when queued.</param>
public sealed record ChangeOutcomeDto(bool Applied, Guid? RequestId);

/// <summary>A change waiting for (or decided by) a second approver under four-eyes governance.</summary>
/// <param name="Id">The request's identifier, used to approve or reject it.</param>
/// <param name="Kind">
/// What is being changed: <c>AddPermission</c>, <c>RemovePermission</c>, <c>DisableApproval</c> or <c>AssignRole</c>
/// (a break-glass assignment).
/// </param>
/// <param name="RoleId">The role concerned; null for <c>DisableApproval</c>.</param>
/// <param name="Permission">The permission added or removed; null unless <see cref="Kind"/> is a permission change.</param>
/// <param name="TenantId">The tenant the change applies in; null for a global change.</param>
/// <param name="RequestedBy">The user who asked for the change; they can't decide it themselves.</param>
/// <param name="RequestedAt">When the change was requested.</param>
/// <param name="Status">The state of the request: <c>Pending</c>, <c>Approved</c> or <c>Rejected</c>.</param>
/// <param name="DecidedBy">The approver or rejecter; null while pending.</param>
/// <param name="DecidedAt">When the request was decided; null while pending.</param>
/// <param name="Note">The decider's optional note.</param>
/// <param name="TargetUserId">The user who would receive the role; set only for <c>AssignRole</c>.</param>
/// <param name="ScopeKey">The scope the role would be assigned at; set only for <c>AssignRole</c>.</param>
/// <param name="ExpiresAt">When the requested assignment would end; set only for <c>AssignRole</c>.</param>
public sealed record RoleChangeRequestDto(
    Guid Id,
    string Kind,
    Guid? RoleId,
    string? Permission,
    Guid? TenantId,
    Guid RequestedBy,
    DateTimeOffset RequestedAt,
    string Status,
    Guid? DecidedBy,
    DateTimeOffset? DecidedAt,
    string? Note,
    Guid? TargetUserId,
    string? ScopeKey,
    DateTimeOffset? ExpiresAt);

/// <summary>The optional body when approving or rejecting a pending change.</summary>
/// <param name="Note">A note recorded with the decision, e.g. why it was rejected.</param>
public sealed record DecideRoleChangeRequest(string? Note);

/// <summary>Whether four-eyes approval is required, at each level and in effect for the caller's tenant.</summary>
/// <param name="Global">The platform-wide setting; <c>true</c> when never set.</param>
/// <param name="Tenant">The tenant's own setting; null when the tenant has none and inherits the global one.</param>
/// <param name="Effective">The setting that applies: the tenant's, else the global one, else <c>true</c>.</param>
public sealed record ApprovalSettingDto(bool Global, bool? Tenant, bool Effective);

/// <summary>
/// Turns four-eyes approval on or off. Turning it on applies at once; turning it off while it is on needs a second approver.
/// </summary>
/// <param name="Require">True to require a second approver for governed changes.</param>
/// <param name="Global">True to change the platform-wide setting instead of the caller's tenant; platform administrators only.</param>
public sealed record SetApprovalSettingRequest(bool Require, bool Global = false);

/// <summary>
/// Assigns a role to a user. Break-glass roles must carry an expiry and, for non-Root granters, wait for a second approver.
/// </summary>
/// <param name="UserId">The user receiving the role.</param>
/// <param name="RoleId">The role to assign.</param>
/// <param name="TenantId">The tenant the assignment applies in.</param>
/// <param name="ScopeKey">The scope level the role applies at; defaults to <c>tenant</c> and must respect the role's minimum scope.</param>
/// <param name="ScopeInstanceId">The specific scope instance (e.g. a workspace id); null for the tenant scope.</param>
/// <param name="ExpiresAt">When the assignment ends; required for break-glass roles, null otherwise for no expiry.</param>
public sealed record AssignRoleRequest(Guid UserId, Guid RoleId, Guid TenantId, string ScopeKey = "tenant", Guid? ScopeInstanceId = null, DateTimeOffset? ExpiresAt = null);

/// <summary>A user's role assignment as administrators see it.</summary>
/// <param name="Id">The assignment's identifier, used to revoke or recertify it.</param>
/// <param name="UserId">The user holding the role.</param>
/// <param name="RoleId">The assigned role.</param>
/// <param name="RoleName">The assigned role's name.</param>
/// <param name="TenantId">The tenant the assignment applies in.</param>
/// <param name="ScopeKey">The scope level the role applies at, e.g. <c>tenant</c>.</param>
/// <param name="ScopeInstanceId">The specific scope instance; null for the tenant scope.</param>
/// <param name="ExpiresAt">When the assignment ends; null when it does not expire.</param>
public sealed record AssignmentDto(Guid Id, Guid UserId, Guid RoleId, string RoleName, Guid TenantId, string ScopeKey, Guid? ScopeInstanceId, DateTimeOffset? ExpiresAt);

/// <summary>Extends an assignment after review. Nobody can recertify their own access.</summary>
/// <param name="ExpiresAt">
/// The new expiry; must be in the future and within the configured maximum extension (365 days by default).
/// </param>
public sealed record RecertifyRequest(DateTimeOffset ExpiresAt);

/// <summary>Assigns a role to every member of a tenant group (groups come from provisioning, for example SCIM).</summary>
/// <param name="GroupId">The tenant group whose members receive the role.</param>
/// <param name="RoleId">The role to assign.</param>
/// <param name="TenantId">The tenant the group and assignment belong to.</param>
/// <param name="ScopeKey">The scope level the role applies at; defaults to <c>tenant</c>.</param>
/// <param name="ScopeInstanceId">The specific scope instance; null for the tenant scope.</param>
/// <param name="ExpiresAt">When the assignment ends; null for no expiry.</param>
public sealed record AssignGroupRoleRequest(Guid GroupId, Guid RoleId, Guid TenantId, string ScopeKey = "tenant", Guid? ScopeInstanceId = null, DateTimeOffset? ExpiresAt = null);

/// <summary>A role held by a tenant group, as administrators see it.</summary>
/// <param name="Id">The group assignment's identifier, used to revoke it.</param>
/// <param name="GroupId">The group holding the role.</param>
/// <param name="RoleId">The assigned role.</param>
/// <param name="RoleName">The assigned role's name.</param>
/// <param name="TenantId">The tenant the group and assignment belong to.</param>
/// <param name="ScopeKey">The scope level the role applies at, e.g. <c>tenant</c>.</param>
/// <param name="ScopeInstanceId">The specific scope instance; null for the tenant scope.</param>
/// <param name="ExpiresAt">When the assignment ends; null when it does not expire.</param>
/// <param name="Members">How many users are currently in the group and so receive the role.</param>
public sealed record GroupAssignmentDto(Guid Id, Guid GroupId, Guid RoleId, string RoleName, Guid TenantId, string ScopeKey, Guid? ScopeInstanceId, DateTimeOffset? ExpiresAt, int Members);

/// <summary>Creates or replaces an ABAC policy. The condition is validated on write.</summary>
/// <param name="Name">The policy's name, shown in decision traces.</param>
/// <param name="Description">An optional explanation for administrators.</param>
/// <param name="TargetAction">The permission the policy applies to: an exact code or <c>*</c> for any.</param>
/// <param name="TargetResourceType">The resource type the policy is limited to; null or <c>*</c> means any.</param>
/// <param name="Effect">Whether a match permits or denies; a matching Deny always wins.</param>
/// <param name="ConditionJson">The JSON condition tree, in the grammar of <see cref="ConditionParser"/>.</param>
/// <param name="Priority">Evaluation order; higher priorities are evaluated first. Defaults to <c>0</c>.</param>
/// <param name="Enabled">False to store the policy without evaluating it. Defaults to <c>true</c>.</param>
public sealed record UpsertPolicyRequest(
    string Name,
    string? Description,
    string TargetAction,
    string? TargetResourceType,
    PolicyEffect Effect,
    string ConditionJson,
    int Priority = 0,
    bool Enabled = true);

/// <summary>A dry-run decision against stated facts.</summary>
/// <param name="Action">The permission being checked, e.g. <c>billing.invoice.read</c>.</param>
/// <param name="ResourceType">The resource type, for policies limited to one; null for none.</param>
/// <param name="Attributes">The subject and resource attributes the policy conditions read; null for none.</param>
/// <param name="HasRoleGrant">Whether to assume the caller holds the permission through a role.</param>
/// <param name="IsRoot">Whether to assume the caller is a platform administrator (Root).</param>
public sealed record SimulateRequest(
    string Action,
    string? ResourceType = null,
    IReadOnlyDictionary<string, System.Text.Json.JsonElement>? Attributes = null,
    bool HasRoleGrant = false,
    bool IsRoot = false);

/// <summary>The outcome of a simulated decision.</summary>
/// <param name="Allowed">Whether the decision would allow the action.</param>
/// <param name="Code">The stable reason code, e.g. <c>denied_by_policy</c>.</param>
/// <param name="Reason">A human-readable explanation of the decision.</param>
/// <param name="Trace">
/// Each applicable policy and whether it matched, in evaluation order; empty unless the caller is a platform administrator.
/// </param>
public sealed record SimulateResponse(bool Allowed, string Code, string Reason, IReadOnlyList<PolicyTraceDto> Trace);

/// <summary>One policy's part in a simulated decision.</summary>
/// <param name="PolicyName">The policy's name.</param>
/// <param name="Effect">Whether the policy permits or denies when it matches.</param>
/// <param name="Matched">Whether the policy's condition matched the stated facts.</param>
public sealed record PolicyTraceDto(string PolicyName, PolicyEffect Effect, bool Matched);

/// <summary>Creates or updates a node of the scope hierarchy. Built-in scopes can't be changed.</summary>
/// <param name="Key">The scope's key; normalised to lower case. On update the key in the route wins.</param>
/// <param name="Name">The display name; required.</param>
/// <param name="Description">An optional explanation for administrators.</param>
/// <param name="ParentKey">The key of an existing, broader scope; required, and may not put the scope inside itself.</param>
public sealed record UpsertScopeRequest(string Key, string Name, string? Description, string? ParentKey);

/// <summary>A permission in the catalog: declared by the host or registered by a service.</summary>
/// <param name="Code">The permission code, <c>domain.resource.action</c>.</param>
/// <param name="DisplayName">A human-readable name for administrators.</param>
/// <param name="Domain">The domain the permission belongs to, e.g. <c>billing</c>.</param>
/// <param name="Source">Where it comes from: <c>host</c>, <c>management</c>, or the registering service's name.</param>
/// <param name="Stale">True when its service no longer declares it; kept so existing grants still display.</param>
public sealed record CatalogEntryDto(string Code, string DisplayName, string Domain, string Source, bool Stale);

/// <summary>Helpers for <see cref="PermissionDefinition"/>.</summary>
public static class PermissionDefinitions
{
    /// <summary>Converts definitions to catalog entries for a source.</summary>
    public static CatalogEntryDto ToEntry(this PermissionDefinition definition, string source)
    {
        ArgumentNullException.ThrowIfNull(definition);
        return new CatalogEntryDto(definition.Code, definition.DisplayName, definition.Domain, source, Stale: false);
    }
}

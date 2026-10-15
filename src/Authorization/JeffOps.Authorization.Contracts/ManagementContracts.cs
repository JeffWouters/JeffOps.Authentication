using JeffOps.Authorization.Domain.Permissions;
using JeffOps.Authorization.Domain.Policies;

namespace JeffOps.Authorization.Contracts;

/// <summary>Routes of the management API (administrators), relative to the management service.</summary>
public static class ManagementRoutes
{
    public const string Prefix = "authorization/admin";
    public const string Roles = Prefix + "/roles";
    public const string RoleChanges = Prefix + "/role-changes";
    public const string ApprovalSetting = Prefix + "/approval-setting";
    public const string Assignments = Prefix + "/assignments";
    public const string Policies = Prefix + "/policies";
    public const string Scopes = Prefix + "/scopes";
    public const string Catalog = Prefix + "/permissions";
}

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

public sealed record CreateRoleRequest(string Name, IReadOnlyList<string>? Permissions = null, string? MinScopeKey = null, IReadOnlyList<string>? ComplianceControls = null, bool Global = false);

public sealed record RolePermissionRequest(string Permission);

/// <summary>The outcome of a role or assignment change that may wait for a second approver.</summary>
/// <param name="Applied">True when applied now; false when queued for approval.</param>
/// <param name="RequestId">The approval request, when queued.</param>
public sealed record ChangeOutcomeDto(bool Applied, Guid? RequestId);

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

public sealed record DecideRoleChangeRequest(string? Note);

public sealed record ApprovalSettingDto(bool Global, bool? Tenant, bool Effective);

public sealed record SetApprovalSettingRequest(bool Require, bool Global = false);

public sealed record AssignRoleRequest(Guid UserId, Guid RoleId, Guid TenantId, string ScopeKey = "tenant", Guid? ScopeInstanceId = null, DateTimeOffset? ExpiresAt = null);

public sealed record AssignmentDto(Guid Id, Guid UserId, Guid RoleId, string RoleName, Guid TenantId, string ScopeKey, Guid? ScopeInstanceId, DateTimeOffset? ExpiresAt);

public sealed record RecertifyRequest(DateTimeOffset ExpiresAt);

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
public sealed record SimulateRequest(
    string Action,
    string? ResourceType = null,
    IReadOnlyDictionary<string, System.Text.Json.JsonElement>? Attributes = null,
    bool HasRoleGrant = false,
    bool IsRoot = false);

public sealed record SimulateResponse(bool Allowed, string Code, string Reason, IReadOnlyList<PolicyTraceDto> Trace);

public sealed record PolicyTraceDto(string PolicyName, PolicyEffect Effect, bool Matched);

public sealed record UpsertScopeRequest(string Key, string Name, string? Description, string? ParentKey);

/// <summary>A permission in the catalog: declared by the host or registered by a service.</summary>
public sealed record CatalogEntryDto(string Code, string DisplayName, string Domain, string Source, bool Stale);

public static class PermissionDefinitions
{
    /// <summary>Converts definitions to catalog entries for a source.</summary>
    public static CatalogEntryDto ToEntry(this PermissionDefinition definition, string source)
    {
        ArgumentNullException.ThrowIfNull(definition);
        return new CatalogEntryDto(definition.Code, definition.DisplayName, definition.Domain, source, Stale: false);
    }
}

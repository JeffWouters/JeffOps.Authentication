using JeffOps.Authentication.Abstractions.Messaging;

namespace JeffOps.Authorization.Contracts;

/// <summary>A role's permission set changed. Resource services flush the role → permission map.</summary>
public sealed record RolePermissionsChangedEvent(Guid RoleId) : IntegrationEvent
{
    public const string EventType = "authorization.role.permissions_changed.v1";

    public override string Type => EventType;
}

/// <summary>A role was assigned to a user in a tenant. Resource services flush that user's assignments.</summary>
public sealed record UserRoleAssignedEvent(Guid UserId, Guid TenantId, Guid RoleId) : IntegrationEvent
{
    public const string EventType = "authorization.user_role.assigned.v1";

    public override string Type => EventType;
}

/// <summary>A role was revoked from a user in a tenant. Resource services flush that user's assignments.</summary>
public sealed record UserRoleRevokedEvent(Guid UserId, Guid TenantId, Guid RoleId) : IntegrationEvent
{
    public const string EventType = "authorization.user_role.revoked.v1";

    public override string Type => EventType;
}

/// <summary>
/// A time-boxed privileged (break-glass) grant was created. <see cref="Watchers"/> are the oversight-role holders in the
/// tenant who should be alerted besides the grantee.
/// </summary>
public sealed record PrivilegedAccessGrantedEvent(
    Guid UserId,
    Guid TenantId,
    Guid RoleId,
    string RoleName,
    DateTimeOffset ExpiresAt,
    IReadOnlyList<Guid> Watchers) : IntegrationEvent
{
    public const string EventType = "authorization.privileged_access.granted.v1";

    public override string Type => EventType;
}

/// <summary>An ABAC policy changed. Resource services flush the cached policy set.</summary>
public sealed record PolicyChangedEvent(Guid PolicyId) : IntegrationEvent
{
    public const string EventType = "authorization.policy.changed.v1";

    public override string Type => EventType;
}

/// <summary>The scope hierarchy changed. Resource services flush the cached hierarchy.</summary>
public sealed record ScopesChangedEvent : IntegrationEvent
{
    public const string EventType = "authorization.scopes.changed.v1";

    public override string Type => EventType;
}

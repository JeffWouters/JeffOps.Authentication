using JeffOps.Authentication.Abstractions.Messaging;

namespace JeffOps.Authorization.Contracts;

/// <summary>A role's permission set changed. Resource services flush the role → permission map.</summary>
/// <param name="RoleId">The role whose permissions changed.</param>
public sealed record RolePermissionsChangedEvent(Guid RoleId) : IntegrationEvent
{
    /// <summary>The event name, <c>authorization.role.permissions_changed.v1</c>, used to route it on a broker.</summary>
    public const string EventType = "authorization.role.permissions_changed.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

/// <summary>A role was assigned to a user in a tenant. Resource services flush that user's assignments.</summary>
/// <param name="UserId">The user who received the role.</param>
/// <param name="TenantId">The tenant the assignment applies in.</param>
/// <param name="RoleId">The assigned role.</param>
public sealed record UserRoleAssignedEvent(Guid UserId, Guid TenantId, Guid RoleId) : IntegrationEvent
{
    /// <summary>The event name, <c>authorization.user_role.assigned.v1</c>, used to route it on a broker.</summary>
    public const string EventType = "authorization.user_role.assigned.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

/// <summary>A role was revoked from a user in a tenant. Resource services flush that user's assignments.</summary>
/// <param name="UserId">The user who lost the role.</param>
/// <param name="TenantId">The tenant the assignment applied in.</param>
/// <param name="RoleId">The revoked role.</param>
public sealed record UserRoleRevokedEvent(Guid UserId, Guid TenantId, Guid RoleId) : IntegrationEvent
{
    /// <summary>The event name, <c>authorization.user_role.revoked.v1</c>, used to route it on a broker.</summary>
    public const string EventType = "authorization.user_role.revoked.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

/// <summary>
/// A time-boxed privileged (break-glass) grant was created. <see cref="Watchers"/> are the oversight-role holders in the
/// tenant who should be alerted besides the grantee.
/// </summary>
/// <param name="UserId">The grantee.</param>
/// <param name="TenantId">The tenant the grant applies in.</param>
/// <param name="RoleId">The break-glass role granted.</param>
/// <param name="RoleName">The role's name, so notifications can show it without a lookup.</param>
/// <param name="ExpiresAt">When the grant ends; break-glass grants are always time-boxed.</param>
/// <param name="Watchers">The users to alert besides the grantee.</param>
public sealed record PrivilegedAccessGrantedEvent(
    Guid UserId,
    Guid TenantId,
    Guid RoleId,
    string RoleName,
    DateTimeOffset ExpiresAt,
    IReadOnlyList<Guid> Watchers) : IntegrationEvent
{
    /// <summary>The event name, <c>authorization.privileged_access.granted.v1</c>, used to route it on a broker.</summary>
    public const string EventType = "authorization.privileged_access.granted.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

/// <summary>An ABAC policy changed. Resource services flush the cached policy set.</summary>
/// <param name="PolicyId">The policy that was created, changed or deleted.</param>
public sealed record PolicyChangedEvent(Guid PolicyId) : IntegrationEvent
{
    /// <summary>The event name, <c>authorization.policy.changed.v1</c>, used to route it on a broker.</summary>
    public const string EventType = "authorization.policy.changed.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

/// <summary>The scope hierarchy changed. Resource services flush the cached hierarchy.</summary>
public sealed record ScopesChangedEvent : IntegrationEvent
{
    /// <summary>The event name, <c>authorization.scopes.changed.v1</c>, used to route it on a broker.</summary>
    public const string EventType = "authorization.scopes.changed.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

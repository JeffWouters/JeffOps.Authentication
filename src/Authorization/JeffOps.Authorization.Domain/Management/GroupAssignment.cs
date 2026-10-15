using JeffOps.Authentication.SharedKernel.Domain;
using JeffOps.Authorization.Domain.Assignments;

namespace JeffOps.Authorization.Domain.Management;

/// <summary>
/// A role assigned to a group in a tenant: every member holds it, as long as they are a member. Groups come from provisioning
/// (SCIM) or the host; their membership is mirrored in <see cref="GroupMember"/>.
/// </summary>
public sealed class GroupAssignment : AggregateRoot<Guid>
{
    private GroupAssignment(Guid id, Guid groupId, Guid roleId, Guid tenantId, string scopeKey, Guid? scopeInstanceId, DateTimeOffset? expiresAt, Guid? grantedBy, DateTimeOffset now)
        : base(id)
    {
        GroupId = groupId;
        RoleId = roleId;
        TenantId = tenantId;
        ScopeKey = scopeKey;
        ScopeInstanceId = scopeInstanceId;
        ExpiresAt = expiresAt;
        GrantedBy = grantedBy;
        GrantedAt = now;
    }

    private GroupAssignment()
    {
    }

    public Guid GroupId { get; private set; }

    public Guid RoleId { get; private set; }

    public Guid TenantId { get; private set; }

    public string ScopeKey { get; private set; } = string.Empty;

    public Guid? ScopeInstanceId { get; private set; }

    public DateTimeOffset? ExpiresAt { get; private set; }

    public Guid? GrantedBy { get; private set; }

    public DateTimeOffset GrantedAt { get; private set; }

    public static GroupAssignment Grant(Guid groupId, Guid roleId, Guid tenantId, string scopeKey, Guid? scopeInstanceId, DateTimeOffset? expiresAt, Guid? grantedBy, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scopeKey);
        return new GroupAssignment(Guid.CreateVersion7(now), groupId, roleId, tenantId, scopeKey.Trim().ToLowerInvariant(), scopeInstanceId, expiresAt, grantedBy, now);
    }

    public bool IsExpired(DateTimeOffset now) => AssignmentExpiry.IsExpired(ExpiresAt, now);

    public RoleAssignment ToRoleAssignment() => new(RoleId, ScopeKey, ScopeInstanceId, ExpiresAt);
}

/// <summary>A user's membership of a group, as the group's source last reported it.</summary>
public sealed class GroupMember
{
    public GroupMember(Guid tenantId, Guid groupId, Guid userId)
    {
        TenantId = tenantId;
        GroupId = groupId;
        UserId = userId;
    }

    private GroupMember()
    {
    }

    public Guid TenantId { get; private set; }

    public Guid GroupId { get; private set; }

    public Guid UserId { get; private set; }
}

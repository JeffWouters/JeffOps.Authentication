using JeffOps.Authentication.SharedKernel.Domain;
using JeffOps.Authorization.Domain.Assignments;

namespace JeffOps.Authorization.Domain.Management;

/// <summary>
/// A role assigned to a user in a tenant, at a scope, optionally confined to one scope instance and optionally expiring.
/// </summary>
public sealed class Assignment : AggregateRoot<Guid>
{
    private Assignment(Guid id, Guid userId, Guid roleId, Guid tenantId, string scopeKey, Guid? scopeInstanceId, DateTimeOffset? expiresAt, Guid? grantedBy, DateTimeOffset now)
        : base(id)
    {
        UserId = userId;
        RoleId = roleId;
        TenantId = tenantId;
        ScopeKey = scopeKey;
        ScopeInstanceId = scopeInstanceId;
        ExpiresAt = expiresAt;
        GrantedBy = grantedBy;
        GrantedAt = now;
    }

    private Assignment()
    {
    }

    public Guid UserId { get; private set; }

    public Guid RoleId { get; private set; }

    public Guid TenantId { get; private set; }

    public string ScopeKey { get; private set; } = string.Empty;

    public Guid? ScopeInstanceId { get; private set; }

    public DateTimeOffset? ExpiresAt { get; private set; }

    public Guid? GrantedBy { get; private set; }

    public DateTimeOffset GrantedAt { get; private set; }

    public static Assignment Grant(Guid userId, Guid roleId, Guid tenantId, string scopeKey, Guid? scopeInstanceId, DateTimeOffset? expiresAt, Guid? grantedBy, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scopeKey);

        var assignment = new Assignment(Guid.CreateVersion7(now), userId, roleId, tenantId, scopeKey.Trim().ToLowerInvariant(), scopeInstanceId, expiresAt, grantedBy, now);
        assignment.Raise(new RoleAssigned(userId, tenantId, roleId));
        return assignment;
    }

    public bool IsExpired(DateTimeOffset now) => AssignmentExpiry.IsExpired(ExpiresAt, now);

    public void Recertify(DateTimeOffset newExpiresAt) => ExpiresAt = newExpiresAt;

    /// <summary>Announces a time-boxed privileged grant to the oversight watchers.</summary>
    public void AnnouncePrivileged(string roleName, IReadOnlyList<Guid> watchers) =>
        Raise(new PrivilegedAccessGranted(UserId, TenantId, RoleId, roleName, ExpiresAt ?? GrantedAt, watchers));

    /// <summary>Marks the assignment revoked; the repository deletes it.</summary>
    public void Revoke() => Raise(new RoleRevoked(UserId, TenantId, RoleId));

    public RoleAssignment ToRoleAssignment() => new(RoleId, ScopeKey, ScopeInstanceId, ExpiresAt);
}

public sealed record RoleAssigned(Guid UserId, Guid TenantId, Guid RoleId) : IDomainEvent;

public sealed record RoleRevoked(Guid UserId, Guid TenantId, Guid RoleId) : IDomainEvent;

public sealed record PrivilegedAccessGranted(Guid UserId, Guid TenantId, Guid RoleId, string RoleName, DateTimeOffset ExpiresAt, IReadOnlyList<Guid> Watchers) : IDomainEvent;

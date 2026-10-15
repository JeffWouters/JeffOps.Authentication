using JeffOps.Authentication.SharedKernel.Domain;
using JeffOps.Authorization.Domain.Permissions;

namespace JeffOps.Authorization.Domain.Management;

public enum RoleChangeKind
{
    AddPermission = 0,
    RemovePermission = 1,

    /// <summary>Turning the four-eyes requirement off; while it is on, that too needs a second approver.</summary>
    DisableApproval = 2,

    /// <summary>Assigning a break-glass role; a non-Root grant waits for a second approver.</summary>
    AssignRole = 3,
}

public enum RoleChangeStatus
{
    Pending = 0,
    Approved = 1,
    Rejected = 2,
}

/// <summary>
/// A change that needs a second person (four-eyes): a role-permission edit, disabling the approval requirement, or a
/// break-glass assignment. The requester can't decide their own request.
/// </summary>
public sealed class RoleChangeRequest : AggregateRoot<Guid>
{
    private RoleChangeRequest(Guid id, RoleChangeKind kind, Guid? roleId, string? permissionCode, Guid? tenantId, Guid requestedBy, DateTimeOffset now)
        : base(id)
    {
        Kind = kind;
        RoleId = roleId;
        PermissionCode = permissionCode;
        TenantId = tenantId;
        RequestedBy = requestedBy;
        RequestedAt = now;
        Status = RoleChangeStatus.Pending;
    }

    private RoleChangeRequest()
    {
    }

    public RoleChangeKind Kind { get; private set; }

    public Guid? RoleId { get; private set; }

    public string? PermissionCode { get; private set; }

    /// <summary>The tenant the change governs; null for global changes.</summary>
    public Guid? TenantId { get; private set; }

    public Guid RequestedBy { get; private set; }

    public DateTimeOffset RequestedAt { get; private set; }

    public RoleChangeStatus Status { get; private set; }

    public Guid? DecidedBy { get; private set; }

    public DateTimeOffset? DecidedAt { get; private set; }

    public string? Note { get; private set; }

    // Break-glass assignment requests.
    public Guid? TargetUserId { get; private set; }

    public string? ScopeKey { get; private set; }

    public Guid? ScopeInstanceId { get; private set; }

    public DateTimeOffset? ExpiresAt { get; private set; }

    public static RoleChangeRequest PermissionChange(RoleChangeKind kind, Guid roleId, string permissionCode, Guid? tenantId, Guid requestedBy, DateTimeOffset now) =>
        kind is RoleChangeKind.AddPermission or RoleChangeKind.RemovePermission
            ? new RoleChangeRequest(Guid.CreateVersion7(now), kind, roleId, Permission.Normalize(permissionCode), tenantId, requestedBy, now)
            : throw new ArgumentOutOfRangeException(nameof(kind));

    public static RoleChangeRequest DisableApproval(Guid? tenantId, Guid requestedBy, DateTimeOffset now) =>
        new(Guid.CreateVersion7(now), RoleChangeKind.DisableApproval, null, null, tenantId, requestedBy, now);

    public static RoleChangeRequest AssignBreakGlass(Guid roleId, Guid targetUserId, Guid tenantId, string scopeKey, Guid? scopeInstanceId, DateTimeOffset expiresAt, Guid requestedBy, DateTimeOffset now) =>
        new(Guid.CreateVersion7(now), RoleChangeKind.AssignRole, roleId, null, tenantId, requestedBy, now)
        {
            TargetUserId = targetUserId,
            ScopeKey = scopeKey.Trim().ToLowerInvariant(),
            ScopeInstanceId = scopeInstanceId,
            ExpiresAt = expiresAt,
        };

    /// <summary>Records the decision. The requester may not decide their own request.</summary>
    /// <exception cref="InvalidOperationException">Already decided, or decided by the requester.</exception>
    public void Decide(bool approve, Guid decidedBy, string? note, DateTimeOffset now)
    {
        if (Status != RoleChangeStatus.Pending)
        {
            throw new InvalidOperationException("The request has already been decided.");
        }

        if (decidedBy == RequestedBy)
        {
            throw new InvalidOperationException("A request can't be decided by the person who made it.");
        }

        Status = approve ? RoleChangeStatus.Approved : RoleChangeStatus.Rejected;
        DecidedBy = decidedBy;
        DecidedAt = now;
        Note = string.IsNullOrWhiteSpace(note) ? Note : note.Trim();
    }
}

/// <summary>Whether role changes need four-eyes approval: per tenant, with a global default.</summary>
public sealed class ApprovalSetting
{
    private ApprovalSetting(Guid? tenantId, bool requireApproval, Guid? updatedBy, DateTimeOffset now)
    {
        Id = Guid.CreateVersion7(now);
        TenantId = tenantId;
        RequireApproval = requireApproval;
        UpdatedBy = updatedBy;
        UpdatedAt = now;
    }

    private ApprovalSetting()
    {
    }

    public Guid Id { get; private set; }

    /// <summary>Null for the global default.</summary>
    public Guid? TenantId { get; private set; }

    public bool RequireApproval { get; private set; }

    public Guid? UpdatedBy { get; private set; }

    public DateTimeOffset UpdatedAt { get; private set; }

    public static ApprovalSetting Create(Guid? tenantId, bool requireApproval, Guid? updatedBy, DateTimeOffset now) => new(tenantId, requireApproval, updatedBy, now);

    public void Set(bool requireApproval, Guid? updatedBy, DateTimeOffset now)
    {
        RequireApproval = requireApproval;
        UpdatedBy = updatedBy;
        UpdatedAt = now;
    }

    /// <summary>The effective requirement: the tenant's setting, else the global one, else required.</summary>
    public static bool Effective(ApprovalSetting? tenant, ApprovalSetting? global) => tenant?.RequireApproval ?? global?.RequireApproval ?? true;
}

/// <summary>A permission a service declared to the registry.</summary>
public sealed class RegisteredPermission
{
    private RegisteredPermission(string code, string displayName, string domain, string source, DateTimeOffset now)
    {
        Code = code;
        DisplayName = displayName;
        Domain = domain;
        Source = source;
        FirstSeenAt = now;
        LastSeenAt = now;
    }

    private RegisteredPermission()
    {
    }

    public string Code { get; private set; } = string.Empty;

    public string DisplayName { get; private set; } = string.Empty;

    public string Domain { get; private set; } = string.Empty;

    /// <summary>The registering service, e.g. <c>svc-billing</c>.</summary>
    public string Source { get; private set; } = string.Empty;

    public DateTimeOffset FirstSeenAt { get; private set; }

    public DateTimeOffset LastSeenAt { get; private set; }

    /// <summary>No longer declared by its source; kept so existing grants keep their display name.</summary>
    public bool Stale { get; private set; }

    public static RegisteredPermission Create(string code, string displayName, string domain, string source, DateTimeOffset now) =>
        new(Permission.Normalize(code), displayName, domain, source, now);

    public void Refresh(string displayName, string domain, string source, DateTimeOffset now)
    {
        DisplayName = displayName;
        Domain = domain;
        Source = source;
        LastSeenAt = now;
        Stale = false;
    }

    public void MarkStale() => Stale = true;
}

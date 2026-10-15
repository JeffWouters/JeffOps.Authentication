using JeffOps.Authorization.Domain.Management;
using JeffOps.Authorization.Domain.Permissions;

namespace JeffOps.Authorization.Application.Abstractions;

public interface IRoleRepository
{
    Task<Role?> FindAsync(Guid roleId, CancellationToken cancellationToken);

    /// <summary>Global roles plus, when given, the custom roles of <paramref name="tenantId"/>.</summary>
    Task<IReadOnlyList<Role>> ListAsync(Guid? tenantId, CancellationToken cancellationToken);

    Task<IReadOnlyList<Role>> ListAllAsync(CancellationToken cancellationToken);

    void Add(Role role);
}

public interface IAssignmentRepository
{
    Task<Assignment?> FindAsync(Guid assignmentId, CancellationToken cancellationToken);

    Task<IReadOnlyList<Assignment>> ListForUserAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken);

    Task<IReadOnlyList<Assignment>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken);

    /// <summary>Assignments that have an expiry (the sweeper filters by time in memory).</summary>
    Task<IReadOnlyList<Assignment>> ListExpiringAsync(CancellationToken cancellationToken);

    void Add(Assignment assignment);

    void Remove(Assignment assignment);
}

public interface IGroupAssignmentRepository
{
    Task<GroupAssignment?> FindAsync(Guid assignmentId, CancellationToken cancellationToken);

    /// <summary>The group assignments that reach <paramref name="userId"/> through their group memberships in the tenant.</summary>
    Task<IReadOnlyList<GroupAssignment>> ListForUserAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken);

    Task<IReadOnlyList<GroupAssignment>> ListForGroupAsync(Guid tenantId, Guid groupId, CancellationToken cancellationToken);

    Task<IReadOnlyList<GroupAssignment>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken);

    void Add(GroupAssignment assignment);

    void Remove(GroupAssignment assignment);
}

/// <summary>The mirrored membership of tenant groups.</summary>
public interface IGroupMemberRepository
{
    Task<IReadOnlyList<Guid>> ListMembersAsync(Guid tenantId, Guid groupId, CancellationToken cancellationToken);

    /// <summary>Makes <paramref name="members"/> the group's members.</summary>
    Task ReplaceAsync(Guid tenantId, Guid groupId, IReadOnlyCollection<Guid> members, CancellationToken cancellationToken);
}

public interface IRoleChangeRepository
{
    Task<RoleChangeRequest?> FindAsync(Guid requestId, CancellationToken cancellationToken);

    Task<IReadOnlyList<RoleChangeRequest>> ListAsync(Guid? tenantId, bool allTenants, RoleChangeStatus? status, CancellationToken cancellationToken);

    void Add(RoleChangeRequest request);
}

public interface IApprovalSettingRepository
{
    Task<ApprovalSetting?> GetAsync(Guid? tenantId, CancellationToken cancellationToken);

    void Add(ApprovalSetting setting);
}

public interface IPolicyRepository
{
    Task<StoredPolicy?> FindAsync(Guid policyId, CancellationToken cancellationToken);

    Task<IReadOnlyList<StoredPolicy>> ListAsync(CancellationToken cancellationToken);

    void Add(StoredPolicy policy);

    void Remove(StoredPolicy policy);
}

public interface IScopeRepository
{
    Task<IReadOnlyList<Scope>> ListAsync(CancellationToken cancellationToken);

    void Add(Scope scope);

    void Remove(Scope scope);
}

public interface IRegisteredPermissionRepository
{
    Task<IReadOnlyList<RegisteredPermission>> ListAsync(CancellationToken cancellationToken);

    void Add(RegisteredPermission permission);
}

public interface IUnitOfWork
{
    Task SaveChangesAsync(CancellationToken cancellationToken);
}

/// <summary>The host's static permission catalog (docs/DESIGN.md §13).</summary>
public interface IPermissionCatalogProvider
{
    IReadOnlyList<PermissionDefinition> Definitions { get; }
}

/// <summary>A built-in role the host ships, seeded and kept in sync at startup.</summary>
public sealed record BuiltInRole(string Name, IReadOnlyList<string> Permissions)
{
    public bool IsSuperAdmin { get; init; }

    public bool IsBreakGlass { get; init; }

    public string? MinScopeKey { get; init; }

    public IReadOnlyList<string> ComplianceControls { get; init; } = [];
}

/// <summary>The host's built-in roles.</summary>
public interface IBuiltInRoleProvider
{
    IReadOnlyList<BuiltInRole> Roles { get; }
}

/// <summary>A seeded scope.</summary>
public sealed record SeedScope(string Key, string Name, string? ParentKey);

/// <summary>The scopes seeded at startup. The default is <c>system → organization → tenant → workspace</c>.</summary>
public interface IScopeSeedProvider
{
    IReadOnlyList<SeedScope> Scopes { get; }
}

internal sealed class EmptyCatalog : IPermissionCatalogProvider, IBuiltInRoleProvider
{
    public IReadOnlyList<PermissionDefinition> Definitions { get; } = [];

    public IReadOnlyList<BuiltInRole> Roles { get; } = [];
}

internal sealed class DefaultScopeSeed : IScopeSeedProvider
{
    public IReadOnlyList<SeedScope> Scopes { get; } =
    [
        new("system", "System", null),
        new("organization", "Organization", "system"),
        new("tenant", "Tenant", "organization"),
        new("workspace", "Workspace", "tenant"),
    ];
}

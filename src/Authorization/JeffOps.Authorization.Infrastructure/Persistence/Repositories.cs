using JeffOps.Authentication.SharedKernel.Domain;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Domain.Management;
using Microsoft.EntityFrameworkCore;

namespace JeffOps.Authorization.Infrastructure.Persistence;

/// <summary>The store read for decisions and escalation checks, without tracking.</summary>
internal sealed class AuthorizationReads(AuthorizationDbContext db) : IAuthorizationReads
{
    public async Task<IReadOnlyList<Domain.Assignments.RoleAssignment>> AssignmentsOfAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken)
    {
        var direct = await db.Assignments.AsNoTracking()
            .Where(assignment => assignment.UserId == userId && assignment.TenantId == tenantId)
            .Select(assignment => new Domain.Assignments.RoleAssignment(assignment.RoleId, assignment.ScopeKey, assignment.ScopeInstanceId, assignment.ExpiresAt))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var viaGroups = await db.GroupAssignments.AsNoTracking()
            .Where(assignment => assignment.TenantId == tenantId
                && db.GroupMembers.Any(member => member.TenantId == tenantId && member.GroupId == assignment.GroupId && member.UserId == userId))
            .Select(assignment => new Domain.Assignments.RoleAssignment(assignment.RoleId, assignment.ScopeKey, assignment.ScopeInstanceId, assignment.ExpiresAt))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return [.. direct, .. viaGroups];
    }

    public async Task<IReadOnlyDictionary<Guid, string[]>> RolePermissionsAsync(IReadOnlyCollection<Guid>? roleIds, CancellationToken cancellationToken)
    {
        var query = db.Roles.AsNoTracking();
        if (roleIds is not null)
        {
            query = query.Where(role => roleIds.Contains(role.Id));
        }

        return (await query.ToListAsync(cancellationToken).ConfigureAwait(false)).ToDictionary(role => role.Id, role => role.PermissionCodes().ToArray());
    }

    public async Task<IReadOnlyList<StoredPolicy>> PoliciesAsync(CancellationToken cancellationToken) =>
        await db.Policies.AsNoTracking().ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<Scope>> ScopesAsync(CancellationToken cancellationToken) =>
        await db.Scopes.AsNoTracking().ToListAsync(cancellationToken).ConfigureAwait(false);
}

internal sealed class RoleRepository(AuthorizationDbContext db) : IRoleRepository
{
    public Task<Role?> FindAsync(Guid roleId, CancellationToken cancellationToken) =>
        db.Roles.FirstOrDefaultAsync(role => role.Id == roleId, cancellationToken);

    public async Task<IReadOnlyList<Role>> ListAsync(Guid? tenantId, CancellationToken cancellationToken) =>
        await db.Roles.Where(role => role.TenantId == null || role.TenantId == tenantId).ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<Role>> ListAllAsync(CancellationToken cancellationToken) =>
        await db.Roles.ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(Role role) => db.Roles.Add(role);
}

internal sealed class AssignmentRepository(AuthorizationDbContext db) : IAssignmentRepository
{
    public Task<Assignment?> FindAsync(Guid assignmentId, CancellationToken cancellationToken) =>
        db.Assignments.FirstOrDefaultAsync(assignment => assignment.Id == assignmentId, cancellationToken);

    public async Task<IReadOnlyList<Assignment>> ListForUserAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken) =>
        await db.Assignments.Where(assignment => assignment.UserId == userId && assignment.TenantId == tenantId).ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<Assignment>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        await db.Assignments.Where(assignment => assignment.TenantId == tenantId).ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<Assignment>> ListExpiringAsync(CancellationToken cancellationToken) =>
        await db.Assignments.Where(assignment => assignment.ExpiresAt != null).ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(Assignment assignment) => db.Assignments.Add(assignment);

    public void Remove(Assignment assignment) => db.Assignments.Remove(assignment);
}

internal sealed class RoleChangeRepository(AuthorizationDbContext db) : IRoleChangeRepository
{
    public Task<RoleChangeRequest?> FindAsync(Guid requestId, CancellationToken cancellationToken) =>
        db.RoleChangeRequests.FirstOrDefaultAsync(request => request.Id == requestId, cancellationToken);

    public async Task<IReadOnlyList<RoleChangeRequest>> ListAsync(Guid? tenantId, bool allTenants, RoleChangeStatus? status, CancellationToken cancellationToken)
    {
        var query = db.RoleChangeRequests.AsQueryable();
        if (!allTenants)
        {
            query = query.Where(request => request.TenantId == tenantId);
        }

        if (status is { } wanted)
        {
            query = query.Where(request => request.Status == wanted);
        }

        return await query.ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    public void Add(RoleChangeRequest request) => db.RoleChangeRequests.Add(request);
}

internal sealed class ApprovalSettingRepository(AuthorizationDbContext db) : IApprovalSettingRepository
{
    public Task<ApprovalSetting?> GetAsync(Guid? tenantId, CancellationToken cancellationToken) =>
        db.ApprovalSettings.FirstOrDefaultAsync(setting => setting.TenantId == tenantId, cancellationToken);

    public void Add(ApprovalSetting setting) => db.ApprovalSettings.Add(setting);
}

internal sealed class PolicyRepository(AuthorizationDbContext db) : IPolicyRepository
{
    public Task<StoredPolicy?> FindAsync(Guid policyId, CancellationToken cancellationToken) =>
        db.Policies.FirstOrDefaultAsync(policy => policy.Id == policyId, cancellationToken);

    public async Task<IReadOnlyList<StoredPolicy>> ListAsync(CancellationToken cancellationToken) =>
        await db.Policies.ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(StoredPolicy policy) => db.Policies.Add(policy);

    public void Remove(StoredPolicy policy) => db.Policies.Remove(policy);
}

internal sealed class ScopeRepository(AuthorizationDbContext db) : IScopeRepository
{
    public async Task<IReadOnlyList<Scope>> ListAsync(CancellationToken cancellationToken) =>
        await db.Scopes.ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(Scope scope) => db.Scopes.Add(scope);

    public void Remove(Scope scope) => db.Scopes.Remove(scope);
}

internal sealed class RegisteredPermissionRepository(AuthorizationDbContext db) : IRegisteredPermissionRepository
{
    public async Task<IReadOnlyList<RegisteredPermission>> ListAsync(CancellationToken cancellationToken) =>
        await db.RegisteredPermissions.ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(RegisteredPermission permission) => db.RegisteredPermissions.Add(permission);
}

internal sealed class GroupAssignmentRepository(AuthorizationDbContext db) : IGroupAssignmentRepository
{
    public Task<GroupAssignment?> FindAsync(Guid assignmentId, CancellationToken cancellationToken) =>
        db.GroupAssignments.FirstOrDefaultAsync(assignment => assignment.Id == assignmentId, cancellationToken);

    public async Task<IReadOnlyList<GroupAssignment>> ListForUserAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken) =>
        await db.GroupAssignments
            .Where(assignment => assignment.TenantId == tenantId
                && db.GroupMembers.Any(member => member.TenantId == tenantId && member.GroupId == assignment.GroupId && member.UserId == userId))
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<GroupAssignment>> ListForGroupAsync(Guid tenantId, Guid groupId, CancellationToken cancellationToken) =>
        await db.GroupAssignments.Where(assignment => assignment.TenantId == tenantId && assignment.GroupId == groupId).ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<GroupAssignment>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        await db.GroupAssignments.Where(assignment => assignment.TenantId == tenantId).ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(GroupAssignment assignment) => db.GroupAssignments.Add(assignment);

    public void Remove(GroupAssignment assignment) => db.GroupAssignments.Remove(assignment);
}

internal sealed class GroupMemberRepository(AuthorizationDbContext db) : IGroupMemberRepository
{
    public async Task<IReadOnlyList<Guid>> ListMembersAsync(Guid tenantId, Guid groupId, CancellationToken cancellationToken) =>
        await db.GroupMembers.Where(member => member.TenantId == tenantId && member.GroupId == groupId).Select(member => member.UserId).ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task ReplaceAsync(Guid tenantId, Guid groupId, IReadOnlyCollection<Guid> members, CancellationToken cancellationToken)
    {
        var current = await db.GroupMembers.Where(member => member.TenantId == tenantId && member.GroupId == groupId).ToListAsync(cancellationToken).ConfigureAwait(false);
        var wanted = members.ToHashSet();
        db.GroupMembers.RemoveRange(current.Where(member => !wanted.Contains(member.UserId)));
        db.GroupMembers.AddRange(wanted.Where(user => current.All(member => member.UserId != user)).Select(user => new GroupMember(tenantId, groupId, user)));
    }

    public async Task<GroupSyncState> SyncStateAsync(Guid tenantId, Guid groupId, CancellationToken cancellationToken)
    {
        if (await db.GroupSyncStates.FirstOrDefaultAsync(state => state.TenantId == tenantId && state.GroupId == groupId, cancellationToken).ConfigureAwait(false) is { } existing)
        {
            return existing;
        }

        var created = new GroupSyncState(tenantId, groupId);
        db.GroupSyncStates.Add(created);
        return created;
    }
}

/// <summary>Saves, then dispatches the domain events of the saved aggregates (including deleted ones).</summary>
internal sealed class EfUnitOfWork(AuthorizationDbContext db, IDomainEventDispatcher dispatcher) : IUnitOfWork
{
    public async Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        var aggregates = db.ChangeTracker.Entries<IHasDomainEvents>().Select(entry => entry.Entity).Where(entity => entity.DomainEvents.Count > 0).ToList();
        var events = aggregates.SelectMany(aggregate => aggregate.DomainEvents).ToList();

        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        foreach (var aggregate in aggregates)
        {
            aggregate.ClearDomainEvents();
        }

        await dispatcher.DispatchAsync(events, cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> TrySaveChangesAsync(CancellationToken cancellationToken)
    {
        try
        {
            await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (DbUpdateConcurrencyException)
        {
            return false;
        }
    }
}

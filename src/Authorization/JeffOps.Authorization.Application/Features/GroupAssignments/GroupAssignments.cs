using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Application.Management;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Management;

namespace JeffOps.Authorization.Application.Features.GroupAssignments;

/// <summary>
/// Assigns a role to a tenant group. The same checks as a user assignment apply; a group the caller belongs to counts as
/// granting to themselves, and break-glass roles are never granted to groups (they are personal and time-boxed).
/// </summary>
public sealed record AssignGroupRoleCommand(ManagementCaller Caller, AssignGroupRoleRequest Request);

public sealed class AssignGroupRoleHandler(
    IRoleRepository roles,
    IGroupAssignmentRepository assignments,
    IGroupMemberRepository members,
    IUnitOfWork unitOfWork,
    ManagementGuard guard,
    HeldPermissions held,
    ManagementAudit audit,
    IEventPublisher events,
    TimeProvider time) : ICommandHandler<AssignGroupRoleCommand, GroupAssignmentDto>
{
    public async Task<Result<GroupAssignmentDto>> HandleAsync(AssignGroupRoleCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var (caller, request) = command;
        var scopeKey = Scope.Normalize(request.ScopeKey);
        var now = time.GetUtcNow();

        var role = await roles.FindAsync(request.RoleId, cancellationToken).ConfigureAwait(false);
        if (role is null || (role.TenantId is { } owner && owner != request.TenantId))
        {
            return Error.NotFound(ManagementErrors.NotFound, "No such role in this tenant.");
        }

        if (role.IsBreakGlass)
        {
            return Error.Failure(ManagementErrors.InvalidScope, "Break-glass roles are assigned to people, not groups.");
        }

        if (await guard.RequireAsync(caller, request.TenantId, guard.Options.Permissions.AssignmentsWrite, cancellationToken, scopeKey, request.ScopeInstanceId).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        if (!AssignmentRules.ScopeAllowed(role, scopeKey, await held.TreeAsync(cancellationToken).ConfigureAwait(false)))
        {
            return Error.Failure(ManagementErrors.InvalidScope, $"'{role.Name}' can't be assigned at '{scopeKey}'.");
        }

        if (await guard.InstanceOutsideTenantAsync(request.TenantId, scopeKey, request.ScopeInstanceId, cancellationToken).ConfigureAwait(false) is { } foreign)
        {
            return foreign;
        }

        if (AssignmentRules.ExpiryProblem(role, request.ExpiresAt, now, guard.Options.BreakGlassMaxDuration) is { } expiryProblem)
        {
            return Error.Failure(ManagementErrors.InvalidExpiry, expiryProblem);
        }

        var groupMembers = await members.ListMembersAsync(request.TenantId, request.GroupId, cancellationToken).ConfigureAwait(false);
        if (!caller.IsRoot)
        {
            var holds = await held.OfCallerAsync(caller, request.TenantId, scopeKey, request.ScopeInstanceId, cancellationToken).ConfigureAwait(false);
            var selfGrant = caller.UserId is { } user && groupMembers.Contains(user);
            if (AssignmentRules.CeilingViolations(role, holds, selfGrant, guard.Options.PrivilegedPermissions()) is { Count: > 0 } missing)
            {
                return Error.Forbidden(ManagementErrors.Escalation, $"You can't grant '{role.Name}': it carries permissions you don't hold ({string.Join(", ", missing.Take(5))}).");
            }
        }

        var existing = await assignments.ListForGroupAsync(request.TenantId, request.GroupId, cancellationToken).ConfigureAwait(false);
        if (existing.Any(assignment => assignment.RoleId == role.Id && assignment.ScopeKey == scopeKey && assignment.ScopeInstanceId == request.ScopeInstanceId && !assignment.IsExpired(now)))
        {
            return Error.Conflict(ManagementErrors.Duplicate, "The group already has this role at this scope.");
        }

        var grant = GroupAssignment.Grant(request.GroupId, role.Id, request.TenantId, scopeKey, request.ScopeInstanceId, request.ExpiresAt, caller.UserId, now);
        assignments.Add(grant);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await GroupEvents.AnnounceAsync(events, groupMembers, request.TenantId, role.Id, assigned: true, now, cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync("group_assignment.granted", "group_assignment", grant.Id.ToString(), caller, request.TenantId, cancellationToken,
            details: new Dictionary<string, string?> { ["group"] = request.GroupId.ToString(), ["role"] = role.Name, ["scope"] = scopeKey }).ConfigureAwait(false);
        return grant.ToDto(role.Name, groupMembers.Count);
    }
}

public sealed record RevokeGroupAssignmentCommand(ManagementCaller Caller, Guid AssignmentId);

/// <summary>Revokes a group's role. Revoking a privileged role needs the same ceiling as granting it.</summary>
public sealed class RevokeGroupAssignmentHandler(
    IGroupAssignmentRepository assignments,
    IGroupMemberRepository members,
    IRoleRepository roles,
    IUnitOfWork unitOfWork,
    ManagementGuard guard,
    HeldPermissions held,
    ManagementAudit audit,
    IEventPublisher events,
    TimeProvider time) : ICommandHandler<RevokeGroupAssignmentCommand>
{
    public async Task<Result> HandleAsync(RevokeGroupAssignmentCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var caller = command.Caller;

        var assignment = await assignments.FindAsync(command.AssignmentId, cancellationToken).ConfigureAwait(false);
        if (assignment is null || !caller.MayActIn(assignment.TenantId))
        {
            return Error.NotFound(ManagementErrors.NotFound, "No such assignment.");
        }

        if (await guard.RequireAsync(caller, assignment.TenantId, guard.Options.Permissions.AssignmentsWrite, cancellationToken).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        if (!caller.IsRoot
            && await roles.FindAsync(assignment.RoleId, cancellationToken).ConfigureAwait(false) is { } role
            && AssignmentRules.IsPrivileged(role, guard.Options.PrivilegedPermissions()))
        {
            var holds = await held.OfCallerAsync(caller, assignment.TenantId, "tenant", null, cancellationToken).ConfigureAwait(false);
            if (AssignmentRules.Uncovered(holds, role.PermissionCodes()).Count > 0)
            {
                return Error.Forbidden(ManagementErrors.Escalation, $"You can't revoke '{role.Name}': it carries permissions you don't hold.");
            }
        }

        assignments.Remove(assignment);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        var groupMembers = await members.ListMembersAsync(assignment.TenantId, assignment.GroupId, cancellationToken).ConfigureAwait(false);
        await GroupEvents.AnnounceAsync(events, groupMembers, assignment.TenantId, assignment.RoleId, assigned: false, time.GetUtcNow(), cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync("group_assignment.revoked", "group_assignment", assignment.Id.ToString(), caller, assignment.TenantId, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

public sealed record ListGroupAssignmentsQuery(ManagementCaller Caller, Guid TenantId);

public sealed class ListGroupAssignmentsHandler(IGroupAssignmentRepository assignments, IGroupMemberRepository members, IRoleRepository roles, ManagementGuard guard)
    : IQueryHandler<ListGroupAssignmentsQuery, IReadOnlyList<GroupAssignmentDto>>
{
    public async Task<Result<IReadOnlyList<GroupAssignmentDto>>> HandleAsync(ListGroupAssignmentsQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (await guard.RequireAsync(query.Caller, query.TenantId, guard.Options.Permissions.AssignmentsRead, cancellationToken).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        var names = (await roles.ListAsync(query.TenantId, cancellationToken).ConfigureAwait(false)).ToDictionary(role => role.Id, role => role.Name);
        var result = new List<GroupAssignmentDto>();
        foreach (var assignment in await assignments.ListForTenantAsync(query.TenantId, cancellationToken).ConfigureAwait(false))
        {
            var count = (await members.ListMembersAsync(assignment.TenantId, assignment.GroupId, cancellationToken).ConfigureAwait(false)).Count;
            result.Add(assignment.ToDto(names.GetValueOrDefault(assignment.RoleId, "?"), count));
        }

        return result;
    }
}

internal static class GroupEvents
{
    public static GroupAssignmentDto ToDto(this GroupAssignment assignment, string roleName, int members) =>
        new(assignment.Id, assignment.GroupId, assignment.RoleId, roleName, assignment.TenantId, assignment.ScopeKey, assignment.ScopeInstanceId, assignment.ExpiresAt, members);

    /// <summary>Each member's access changed: resource services flush their cached assignments.</summary>
    public static async Task AnnounceAsync(IEventPublisher events, IEnumerable<Guid> users, Guid tenantId, Guid roleId, bool assigned, DateTimeOffset now, CancellationToken cancellationToken)
    {
        foreach (var user in users)
        {
            IntegrationEvent change = assigned
                ? new UserRoleAssignedEvent(user, tenantId, roleId) { OccurredAt = now }
                : new UserRoleRevokedEvent(user, tenantId, roleId) { OccurredAt = now };
            await events.PublishAsync(change, cancellationToken).ConfigureAwait(false);
        }
    }
}

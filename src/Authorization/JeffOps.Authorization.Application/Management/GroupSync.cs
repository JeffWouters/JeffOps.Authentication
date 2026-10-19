using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Management;
using Microsoft.Extensions.Options;

namespace JeffOps.Authorization.Application.Management;

/// <summary>
/// Mirrors tenant group membership from provisioning (SCIM) events, and announces the access change of every member who
/// joined or left a group that holds roles, so resource services flush their cached assignments. When the administrator
/// who granted a group a role joins that group, the grant is checked again as a grant to themselves, and revoked if they
/// don't hold every permission of the role.
/// </summary>
public sealed class GroupSync(
    IGroupMemberRepository members,
    IGroupAssignmentRepository assignments,
    IRoleRepository roles,
    HeldPermissions heldPermissions,
    IUnitOfWork unitOfWork,
    IEventPublisher events,
    ManagementAudit audit,
    IOptions<ManagementOptions> options,
    TimeProvider time) :
    IIntegrationEventHandler<GroupMembershipChangedEvent>,
    IIntegrationEventHandler<GroupDeletedEvent>
{
    public async Task HandleAsync(GroupMembershipChangedEvent integrationEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(integrationEvent);
        var (tenantId, groupId) = (integrationEvent.TenantId, integrationEvent.GroupId);

        // An announcement older than one already applied (they can arrive out of order) is stale: ignore it.
        var state = await members.SyncStateAsync(tenantId, groupId, cancellationToken).ConfigureAwait(false);
        if (!state.TryAdvance(integrationEvent.Version))
        {
            return;
        }

        // Checked before the membership changes, so the grantor's holdings don't include the grant itself.
        var former = await members.ListMembersAsync(tenantId, groupId, cancellationToken).ConfigureAwait(false);
        var selfGrants = await SelfGrantsAsync(tenantId, groupId, integrationEvent.Members.Except(former).ToHashSet(), cancellationToken).ConfigureAwait(false);
        foreach (var (assignment, _) in selfGrants)
        {
            assignments.Remove(assignment);
        }

        await members.ReplaceAsync(tenantId, groupId, [.. integrationEvent.Members], cancellationToken).ConfigureAwait(false);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        var everyone = former.Concat(integrationEvent.Members).Distinct().ToList();
        foreach (var (assignment, role) in selfGrants)
        {
            foreach (var user in everyone)
            {
                await events.PublishAsync(new UserRoleRevokedEvent(user, tenantId, assignment.RoleId) { OccurredAt = time.GetUtcNow() }, cancellationToken).ConfigureAwait(false);
            }

            await audit.WriteAsync("group_assignment.revoked", "group_assignment", assignment.Id.ToString(), new ManagementCaller(null, false, false, null, tenantId, null), tenantId, cancellationToken,
                AuditSeverity.Warning,
                new Dictionary<string, string?> { ["group"] = groupId.ToString(), ["role"] = role.Name, ["reason"] = "grantor_joined_group", ["grantor"] = assignment.GrantedBy?.ToString() }).ConfigureAwait(false);
        }

        await AnnounceAsync(tenantId, groupId, integrationEvent.Added.Concat(integrationEvent.Removed), cancellationToken).ConfigureAwait(false);
    }

    public async Task HandleAsync(GroupDeletedEvent integrationEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(integrationEvent);
        var held = await assignments.ListForGroupAsync(integrationEvent.TenantId, integrationEvent.GroupId, cancellationToken).ConfigureAwait(false);
        foreach (var assignment in held)
        {
            assignments.Remove(assignment);
        }

        (await members.SyncStateAsync(integrationEvent.TenantId, integrationEvent.GroupId, cancellationToken).ConfigureAwait(false)).MarkDeleted();
        await members.ReplaceAsync(integrationEvent.TenantId, integrationEvent.GroupId, [], cancellationToken).ConfigureAwait(false);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        foreach (var user in integrationEvent.FormerMembers)
        {
            foreach (var assignment in held)
            {
                await events.PublishAsync(new UserRoleRevokedEvent(user, integrationEvent.TenantId, assignment.RoleId) { OccurredAt = time.GetUtcNow() }, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    /// <summary>The group's grants whose grantor is joining and doesn't hold every permission of the role.</summary>
    private async Task<List<(GroupAssignment Assignment, Role Role)>> SelfGrantsAsync(Guid tenantId, Guid groupId, IReadOnlySet<Guid> joining, CancellationToken cancellationToken)
    {
        var found = new List<(GroupAssignment, Role)>();
        if (joining.Count == 0)
        {
            return found;
        }

        foreach (var assignment in await assignments.ListForGroupAsync(tenantId, groupId, cancellationToken).ConfigureAwait(false))
        {
            if (assignment.GrantedBy is not { } grantor || !joining.Contains(grantor)
                || await roles.FindAsync(assignment.RoleId, cancellationToken).ConfigureAwait(false) is not { } role)
            {
                continue;
            }

            var holds = await heldPermissions.OfAsync(grantor, tenantId, assignment.ScopeKey, assignment.ScopeInstanceId, cancellationToken).ConfigureAwait(false);
            if (AssignmentRules.CeilingViolations(role, holds, grantingToSelf: true, options.Value.PrivilegedPermissions()).Count > 0)
            {
                found.Add((assignment, role));
            }
        }

        return found;
    }

    private async Task AnnounceAsync(Guid tenantId, Guid groupId, IEnumerable<Guid> users, CancellationToken cancellationToken)
    {
        var held = await assignments.ListForGroupAsync(tenantId, groupId, cancellationToken).ConfigureAwait(false);
        foreach (var user in users.Distinct())
        {
            foreach (var assignment in held)
            {
                await events.PublishAsync(new UserRoleAssignedEvent(user, tenantId, assignment.RoleId) { OccurredAt = time.GetUtcNow() }, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}

using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Contracts;

namespace JeffOps.Authorization.Application.Management;

/// <summary>
/// Mirrors tenant group membership from provisioning (SCIM) events, and announces the access change of every member who
/// joined or left a group that holds roles, so resource services flush their cached assignments.
/// </summary>
public sealed class GroupSync(
    IGroupMemberRepository members,
    IGroupAssignmentRepository assignments,
    IUnitOfWork unitOfWork,
    IEventPublisher events,
    TimeProvider time) :
    IIntegrationEventHandler<GroupMembershipChangedEvent>,
    IIntegrationEventHandler<GroupDeletedEvent>
{
    public async Task HandleAsync(GroupMembershipChangedEvent integrationEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(integrationEvent);
        await members.ReplaceAsync(integrationEvent.TenantId, integrationEvent.GroupId, [.. integrationEvent.Members], cancellationToken).ConfigureAwait(false);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await AnnounceAsync(integrationEvent.TenantId, integrationEvent.GroupId, integrationEvent.Added.Concat(integrationEvent.Removed), cancellationToken).ConfigureAwait(false);
    }

    public async Task HandleAsync(GroupDeletedEvent integrationEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(integrationEvent);
        var held = await assignments.ListForGroupAsync(integrationEvent.TenantId, integrationEvent.GroupId, cancellationToken).ConfigureAwait(false);
        foreach (var assignment in held)
        {
            assignments.Remove(assignment);
        }

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

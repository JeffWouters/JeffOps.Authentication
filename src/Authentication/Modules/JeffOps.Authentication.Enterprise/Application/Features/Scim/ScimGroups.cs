using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.Enterprise.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Enterprise.Application.Features.Scim;

internal static class GroupMapping
{
    public static ScimGroupView ToView(this ScimGroup group) =>
        new(group.Id, group.DisplayName, group.ExternalId, group.MemberIds, group.Created, group.LastModified, group.Version);

    /// <summary>Members must be users provisioned in the same tenant.</summary>
    public static async Task<Error?> CheckMembersAsync(IScimUserRepository users, Guid tenantId, IEnumerable<Guid> members, CancellationToken cancellationToken)
    {
        foreach (var member in members.Distinct())
        {
            if (await users.FindAsync(tenantId, member, cancellationToken).ConfigureAwait(false) is null)
            {
                return Error.Failure(ScimErrors.InvalidValue, $"Member {member} is not a user of this tenant.");
            }
        }

        return null;
    }
}

public sealed record CreateScimGroupCommand(Guid TenantId, string DisplayName, string? ExternalId, IReadOnlyList<Guid> Members);

public sealed class CreateScimGroupHandler(IScimGroupRepository groups, IScimUserRepository users, ScimProvisioning provisioning, IEnterpriseUnitOfWork unitOfWork, TimeProvider time)
    : ICommandHandler<CreateScimGroupCommand, ScimGroupView>
{
    public async Task<Result<ScimGroupView>> HandleAsync(CreateScimGroupCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (string.IsNullOrWhiteSpace(command.DisplayName))
        {
            return Error.Validation([new ValidationFailure("displayName", "A group needs a displayName.")]);
        }

        if ((await groups.ListAsync(command.TenantId, new ScimFilter("displayName", command.DisplayName.Trim()), 0, 1, cancellationToken).ConfigureAwait(false)).Total > 0)
        {
            return Error.Conflict(ScimErrors.Uniqueness, $"A group named '{command.DisplayName}' already exists.");
        }

        if (await GroupMapping.CheckMembersAsync(users, command.TenantId, command.Members, cancellationToken).ConfigureAwait(false) is { } invalid)
        {
            return invalid;
        }

        var now = time.GetUtcNow();
        var group = ScimGroup.Create(command.TenantId, command.DisplayName, command.ExternalId, now);
        group.AddMembers(command.Members, now);
        groups.Add(group);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await provisioning.PublishMembershipAsync(group, group.MemberIds, [], cancellationToken).ConfigureAwait(false);
        return group.ToView();
    }
}

/// <summary>The changes a PUT or PATCH makes to a group. Null leaves an attribute alone.</summary>
public sealed record ScimGroupChange(string? DisplayName = null, string? ExternalId = null, IReadOnlyList<Guid>? ReplaceMembers = null, IReadOnlyList<Guid>? AddMembers = null, IReadOnlyList<Guid>? RemoveMembers = null);

public sealed record UpdateScimGroupCommand(Guid TenantId, Guid GroupId, ScimGroupChange Change);

public sealed class UpdateScimGroupHandler(IScimGroupRepository groups, IScimUserRepository users, ScimProvisioning provisioning, IEnterpriseUnitOfWork unitOfWork, TimeProvider time)
    : ICommandHandler<UpdateScimGroupCommand, ScimGroupView>
{
    public async Task<Result<ScimGroupView>> HandleAsync(UpdateScimGroupCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var change = command.Change;
        var now = time.GetUtcNow();

        var group = await groups.FindAsync(command.TenantId, command.GroupId, cancellationToken).ConfigureAwait(false);
        if (group is null)
        {
            return Error.NotFound(ScimErrors.NotFound, "No such group.");
        }

        var incoming = (change.ReplaceMembers ?? []).Concat(change.AddMembers ?? []);
        if (await GroupMapping.CheckMembersAsync(users, command.TenantId, incoming, cancellationToken).ConfigureAwait(false) is { } invalid)
        {
            return invalid;
        }

        var before = group.MemberIds.ToHashSet();
        if (change.DisplayName is not null || change.ExternalId is not null)
        {
            group.Rename(change.DisplayName ?? group.DisplayName, change.ExternalId ?? group.ExternalId, now);
        }

        if (change.ReplaceMembers is { } replace)
        {
            group.ReplaceMembers(replace, now);
        }

        if (change.AddMembers is { } add)
        {
            group.AddMembers(add, now);
        }

        if (change.RemoveMembers is { } remove)
        {
            group.RemoveMembers(remove, now);
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        var after = group.MemberIds.ToHashSet();
        await provisioning.PublishMembershipAsync(group, [.. after.Except(before)], [.. before.Except(after)], cancellationToken).ConfigureAwait(false);
        return group.ToView();
    }
}

public sealed record DeleteScimGroupCommand(Guid TenantId, Guid GroupId);

public sealed class DeleteScimGroupHandler(IScimGroupRepository groups, IEnterpriseUnitOfWork unitOfWork, IEventPublisher events, TimeProvider time) : ICommandHandler<DeleteScimGroupCommand>
{
    public async Task<Result> HandleAsync(DeleteScimGroupCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var group = await groups.FindAsync(command.TenantId, command.GroupId, cancellationToken).ConfigureAwait(false);
        if (group is null)
        {
            return Error.NotFound(ScimErrors.NotFound, "No such group.");
        }

        var members = group.MemberIds;
        groups.Remove(group);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await events.PublishAsync(new GroupDeletedEvent(group.TenantId, group.Id, members) { OccurredAt = time.GetUtcNow() }, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

public sealed record GetScimGroupQuery(Guid TenantId, Guid GroupId);

public sealed class GetScimGroupHandler(IScimGroupRepository groups) : IQueryHandler<GetScimGroupQuery, ScimGroupView>
{
    public async Task<Result<ScimGroupView>> HandleAsync(GetScimGroupQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        return await groups.FindAsync(query.TenantId, query.GroupId, cancellationToken).ConfigureAwait(false) is { } group
            ? group.ToView()
            : Error.NotFound(ScimErrors.NotFound, "No such group.");
    }
}

public sealed record ListScimGroupsQuery(Guid TenantId, ScimFilter? Filter, int StartIndex, int Count);

public sealed class ListScimGroupsHandler(IScimGroupRepository groups) : IQueryHandler<ListScimGroupsQuery, ScimPage<ScimGroupView>>
{
    public async Task<Result<ScimPage<ScimGroupView>>> HandleAsync(ListScimGroupsQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (query.Filter is { Attribute: var attribute } && attribute is not ("displayName" or "externalId"))
        {
            return Error.Failure(ScimErrors.InvalidFilter, "Groups can be filtered by displayName or externalId (eq).");
        }

        var (page, total) = await groups.ListAsync(query.TenantId, query.Filter, Math.Max(query.StartIndex, 1) - 1, Math.Clamp(query.Count, 0, 200), cancellationToken).ConfigureAwait(false);
        return new ScimPage<ScimGroupView>([.. page.Select(group => group.ToView())], total, Math.Max(query.StartIndex, 1));
    }
}

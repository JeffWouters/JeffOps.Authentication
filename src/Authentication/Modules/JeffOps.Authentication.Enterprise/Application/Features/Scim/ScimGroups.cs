using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.Enterprise.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Enterprise.Application.Features.Scim;

internal static class GroupMapping
{
    public static ScimGroupView ToView(this ScimGroup group) =>
        new(group.Id, group.DisplayName, group.ExternalId, group.MemberIds, group.Created, group.LastModified, group.Version);

    /// <summary>Members must be users provisioned in the same tenant; one request adds at most <see cref="ScimLimits.MaxMembersPerRequest"/>.</summary>
    public static async Task<Error?> CheckMembersAsync(IScimUserRepository users, Guid tenantId, IEnumerable<Guid> members, CancellationToken cancellationToken)
    {
        var wanted = members.Distinct().ToList();
        if (wanted.Count > ScimLimits.MaxMembersPerRequest)
        {
            return Error.Failure(ScimErrors.InvalidValue, $"At most {ScimLimits.MaxMembersPerRequest} members per request.");
        }

        if (wanted.Count == 0)
        {
            return null;
        }

        var known = (await users.FindManyAsync(tenantId, wanted, cancellationToken).ConfigureAwait(false)).Select(user => user.AccountId).ToHashSet();
        return wanted.FirstOrDefault(member => !known.Contains(member)) is var unknown && unknown != Guid.Empty
            ? Error.Failure(ScimErrors.InvalidValue, $"Member {unknown} is not a user of this tenant.")
            : null;
    }

    public static Error? CheckName(string displayName) =>
        displayName.Trim().Length > ScimLimits.MaxLength
            ? Error.Validation([new ValidationFailure("displayName", $"A displayName is limited to {ScimLimits.MaxLength} characters.")])
            : null;
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

        if (GroupMapping.CheckName(command.DisplayName) is { } tooLong)
        {
            return tooLong;
        }

        if ((await groups.ListAsync(command.TenantId, ScimFilters.ForGroups(ScimFilter.Eq("displayName", command.DisplayName.Trim())).Value, 0, 1, null, cancellationToken).ConfigureAwait(false)).Total > 0)
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

/// <summary>Changes a group; <paramref name="IfMatch"/>: the versions the caller allows (<c>If-Match</c>), null for any.</summary>
public sealed record UpdateScimGroupCommand(Guid TenantId, Guid GroupId, ScimGroupChange Change, IReadOnlyList<int>? IfMatch = null);

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

        if (ScimVersions.Check(command.IfMatch, group.Version) is { } changed)
        {
            return changed;
        }

        var incoming = (change.ReplaceMembers ?? []).Concat(change.AddMembers ?? []);
        if (await GroupMapping.CheckMembersAsync(users, command.TenantId, incoming, cancellationToken).ConfigureAwait(false) is { } invalid)
        {
            return invalid;
        }

        if (change.DisplayName is { } newName && !string.Equals(newName.Trim(), group.DisplayName, StringComparison.OrdinalIgnoreCase))
        {
            if (GroupMapping.CheckName(newName) is { } tooLong)
            {
                return tooLong;
            }

            if ((await groups.ListAsync(command.TenantId, ScimFilters.ForGroups(ScimFilter.Eq("displayName", newName.Trim())).Value, 0, 1, null, cancellationToken).ConfigureAwait(false)).Total > 0)
            {
                return Error.Conflict(ScimErrors.Uniqueness, $"A group named '{newName}' already exists.");
            }
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

        if (!await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
        {
            return ScimVersions.Overtaken(command.IfMatch);
        }

        var after = group.MemberIds.ToHashSet();
        await provisioning.PublishMembershipAsync(group, [.. after.Except(before)], [.. before.Except(after)], cancellationToken).ConfigureAwait(false);
        return group.ToView();
    }
}

public sealed record DeleteScimGroupCommand(Guid TenantId, Guid GroupId, IReadOnlyList<int>? IfMatch = null);

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

        if (ScimVersions.Check(command.IfMatch, group.Version) is { } changed)
        {
            return changed;
        }

        var members = group.MemberIds;
        groups.Remove(group);
        if (!await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
        {
            return ScimVersions.Overtaken(command.IfMatch);
        }

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

/// <summary>Lists groups; without <paramref name="IncludeMembers"/> (the answer excludes them) members aren't read.</summary>
public sealed record ListScimGroupsQuery(Guid TenantId, ScimFilter? Filter, int StartIndex, int Count, ScimSort? Sort = null, bool IncludeMembers = true);

public sealed class ListScimGroupsHandler(IScimGroupRepository groups) : IQueryHandler<ListScimGroupsQuery, ScimPage<ScimGroupView>>
{
    public async Task<Result<ScimPage<ScimGroupView>>> HandleAsync(ListScimGroupsQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        System.Linq.Expressions.Expression<Func<Domain.ScimGroup, bool>>? filter = null;
        if (query.Filter is { } given)
        {
            var translated = ScimFilters.ForGroups(given);
            if (translated.IsFailure)
            {
                return translated.Error;
            }

            filter = translated.Value;
        }

        if (query.Sort is { } sort && ScimSort.Canonical(sort.Attribute, ScimSort.Groups) is null)
        {
            return Error.Failure(ScimErrors.InvalidValue, $"Groups can be sorted by {string.Join(", ", ScimSort.Groups)}.");
        }

        var skip = Math.Max(query.StartIndex, 1) - 1;
        var take = Math.Clamp(query.Count, 0, 200);
        var order = query.Sort is { } requested ? requested with { Attribute = ScimSort.Canonical(requested.Attribute, ScimSort.Groups)! } : null;
        if (!query.IncludeMembers)
        {
            var (views, count) = await groups.ListWithoutMembersAsync(query.TenantId, filter, skip, take, order, cancellationToken).ConfigureAwait(false);
            return new ScimPage<ScimGroupView>(views, count, Math.Max(query.StartIndex, 1));
        }

        var (page, total) = await groups.ListAsync(query.TenantId, filter, skip, take, order, cancellationToken).ConfigureAwait(false);
        return new ScimPage<ScimGroupView>([.. page.Select(group => group.ToView())], total, Math.Max(query.StartIndex, 1));
    }
}

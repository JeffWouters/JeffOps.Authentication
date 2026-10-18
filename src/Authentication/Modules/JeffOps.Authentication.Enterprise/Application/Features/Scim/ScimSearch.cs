using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Enterprise.Application.Features.Scim;

/// <summary>A search across users and groups (<c>POST /.search</c>, RFC 7644 §3.4.3), 1-based <paramref name="StartIndex"/>.</summary>
public sealed record SearchScimQuery(Guid TenantId, ScimFilter? Filter, int StartIndex, int Count, ScimSort? Sort, bool IncludeMembers = true);

/// <summary>One page of a search across resource types: users first, then groups.</summary>
public sealed record ScimSearchPage(IReadOnlyList<ScimUserView> Users, IReadOnlyList<ScimGroupView> Groups, int TotalResults, int StartIndex);

/// <summary>
/// Searches users and groups together. An attribute one type doesn't have matches nothing of that type, so
/// <c>userName sw "a"</c> finds only users; users come before groups, each sorted when it has the <c>sortBy</c> attribute.
/// </summary>
public sealed class SearchScimHandler(IScimUserRepository users, IScimGroupRepository groups, ScimProvisioning provisioning) : IQueryHandler<SearchScimQuery, ScimSearchPage>
{
    public async Task<Result<ScimSearchPage>> HandleAsync(SearchScimQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        System.Linq.Expressions.Expression<Func<Domain.ScimUser, bool>>? userFilter = null;
        System.Linq.Expressions.Expression<Func<Domain.ScimGroup, bool>>? groupFilter = null;
        if (query.Filter is { } filter)
        {
            var forUsers = ScimFilters.ForUsers(filter, lenient: true);
            var forGroups = ScimFilters.ForGroups(filter, lenient: true);
            if (forUsers.IsFailure)
            {
                return forUsers.Error;
            }

            if (forGroups.IsFailure)
            {
                return forGroups.Error;
            }

            (userFilter, groupFilter) = (forUsers.Value, forGroups.Value);
        }

        ScimSort? userSort = null;
        ScimSort? groupSort = null;
        if (query.Sort is { } sort)
        {
            userSort = ScimSort.Canonical(sort.Attribute, ScimSort.Users) is { } forUsers ? sort with { Attribute = forUsers } : null;
            groupSort = ScimSort.Canonical(sort.Attribute, ScimSort.Groups) is { } forGroups ? sort with { Attribute = forGroups } : null;
            if (userSort is null && groupSort is null)
            {
                return Error.Failure(ScimErrors.InvalidValue, $"Neither users nor groups can be sorted by '{sort.Attribute}'.");
            }
        }

        var startIndex = Math.Max(query.StartIndex, 1);
        var skip = startIndex - 1;
        var take = Math.Clamp(query.Count, 0, 200);
        var (userPage, userTotal) = await users.ListAsync(query.TenantId, userFilter, skip, take, userSort, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<ScimGroupView> groupViews;
        int groupTotal;
        if (query.IncludeMembers)
        {
            var (groupPage, total) = await groups.ListAsync(query.TenantId, groupFilter, Math.Max(0, skip - userTotal), take - userPage.Count, groupSort, cancellationToken).ConfigureAwait(false);
            (groupViews, groupTotal) = ([.. groupPage.Select(group => group.ToView())], total);
        }
        else
        {
            (groupViews, groupTotal) = await groups.ListWithoutMembersAsync(query.TenantId, groupFilter, Math.Max(0, skip - userTotal), take - userPage.Count, groupSort, cancellationToken).ConfigureAwait(false);
        }

        return new ScimSearchPage(await provisioning.ViewsAsync(userPage, cancellationToken).ConfigureAwait(false), groupViews, userTotal + groupTotal, startIndex);
    }
}

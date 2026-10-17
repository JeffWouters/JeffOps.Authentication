using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Enterprise.Application.Features.Scim;

public sealed record ScimPage<T>(IReadOnlyList<T> Resources, int TotalResults, int StartIndex);

/// <summary>Sizes the store can hold, checked up front so an oversized value is a SCIM 400 rather than a database error.</summary>
internal static class ScimLimits
{
    public const int MaxLength = 256;

    /// <summary>The most members one request may add or set.</summary>
    public const int MaxMembersPerRequest = 1_000;

    /// <summary>The longest given or family name kept.</summary>
    public const int MaxNameLength = 200;

    public static Error? Check(ScimUserData data)
    {
        var failures = new[] { ("userName", data.UserName), ("externalId", data.ExternalId), ("displayName", data.DisplayName), ("emails", data.Email) }
            .Where(field => field.Item2?.Length > MaxLength)
            .Select(field => new ValidationFailure(field.Item1, $"Values are limited to {MaxLength} characters."))
            .Concat(new[] { ("name.givenName", data.GivenName), ("name.familyName", data.FamilyName) }
                .Where(field => field.Item2?.Length > MaxNameLength)
                .Select(field => new ValidationFailure(field.Item1, $"Names are limited to {MaxNameLength} characters.")))
            .ToList();
        return failures.Count == 0 ? null : Error.Validation(failures);
    }
}

public sealed record CreateScimUserCommand(Guid TenantId, ScimUserData Data);

public sealed class CreateScimUserHandler(ScimProvisioning provisioning, IEnterpriseUnitOfWork unitOfWork) : ICommandHandler<CreateScimUserCommand, ScimUserView>
{
    public async Task<Result<ScimUserView>> HandleAsync(CreateScimUserCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (ScimLimits.Check(command.Data) is { } tooLong)
        {
            return tooLong;
        }

        var created = await provisioning.CreateAsync(command.TenantId, command.Data, cancellationToken).ConfigureAwait(false);
        if (created.IsFailure)
        {
            return created.Error;
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return await provisioning.ViewAsync(created.Value, cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>
/// Replaces a user's attributes (PUT), or applies a PATCH: the endpoint turns PATCH operations into the full new state with
/// <see cref="UpdateScimUserCommand.Change"/>, so both paths run the same rules. <paramref name="IfMatch"/>: the versions the
/// caller allows (<c>If-Match</c>); null for any.
/// </summary>
public sealed record UpdateScimUserCommand(Guid TenantId, Guid UserId, Func<ScimUserData, Result<ScimUserData>> Change, IReadOnlyList<int>? IfMatch = null);

public sealed class UpdateScimUserHandler(IScimUserRepository users, ScimProvisioning provisioning, IEnterpriseUnitOfWork unitOfWork)
    : ICommandHandler<UpdateScimUserCommand, ScimUserView>
{
    public async Task<Result<ScimUserView>> HandleAsync(UpdateScimUserCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var user = await users.FindAsync(command.TenantId, command.UserId, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            return Error.NotFound(ScimErrors.NotFound, "No such user.");
        }

        if (ScimVersions.Check(command.IfMatch, user.Version) is { } changed)
        {
            return changed;
        }

        var current = await provisioning.ViewAsync(user, cancellationToken).ConfigureAwait(false);
        var next = command.Change(new ScimUserData(user.UserName, user.ExternalId, user.GivenName, user.FamilyName, user.DisplayName, current.Email, user.Active));
        if (next.IsFailure)
        {
            return next.Error;
        }

        if (ScimLimits.Check(next.Value) is { } tooLong)
        {
            return tooLong;
        }

        var applied = await provisioning.ApplyAsync(user, next.Value, cancellationToken).ConfigureAwait(false);
        if (applied.IsFailure)
        {
            return applied.Error;
        }

        if (!await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
        {
            return ScimVersions.Overtaken(command.IfMatch);
        }

        return await provisioning.ViewAsync(user, cancellationToken).ConfigureAwait(false);
    }
}

public sealed record DeleteScimUserCommand(Guid TenantId, Guid UserId, IReadOnlyList<int>? IfMatch = null);

public sealed class DeleteScimUserHandler(IScimUserRepository users, ScimProvisioning provisioning, IEnterpriseUnitOfWork unitOfWork) : ICommandHandler<DeleteScimUserCommand>
{
    public async Task<Result> HandleAsync(DeleteScimUserCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var user = await users.FindAsync(command.TenantId, command.UserId, cancellationToken).ConfigureAwait(false);
        if (user is null)
        {
            return Error.NotFound(ScimErrors.NotFound, "No such user.");
        }

        if (ScimVersions.Check(command.IfMatch, user.Version) is { } changed)
        {
            return changed;
        }

        if (await provisioning.DeleteAsync(user, cancellationToken).ConfigureAwait(false) is { } failure)
        {
            return failure;
        }

        return await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false) ? Result.Success() : ScimVersions.Overtaken(command.IfMatch);
    }
}

public sealed record GetScimUserQuery(Guid TenantId, Guid UserId);

public sealed class GetScimUserHandler(IScimUserRepository users, ScimProvisioning provisioning) : IQueryHandler<GetScimUserQuery, ScimUserView>
{
    public async Task<Result<ScimUserView>> HandleAsync(GetScimUserQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        return await users.FindAsync(query.TenantId, query.UserId, cancellationToken).ConfigureAwait(false) is { } user
            ? await provisioning.ViewAsync(user, cancellationToken).ConfigureAwait(false)
            : Error.NotFound(ScimErrors.NotFound, "No such user.");
    }
}

/// <summary>Lists users, 1-based <paramref name="StartIndex"/> as SCIM pages.</summary>
public sealed record ListScimUsersQuery(Guid TenantId, ScimFilter? Filter, int StartIndex, int Count, ScimSort? Sort = null);

public sealed class ListScimUsersHandler(IScimUserRepository users, ScimProvisioning provisioning) : IQueryHandler<ListScimUsersQuery, ScimPage<ScimUserView>>
{
    public async Task<Result<ScimPage<ScimUserView>>> HandleAsync(ListScimUsersQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        System.Linq.Expressions.Expression<Func<Domain.ScimUser, bool>>? filter = null;
        if (query.Filter is { } given)
        {
            var translated = ScimFilters.ForUsers(given);
            if (translated.IsFailure)
            {
                return translated.Error;
            }

            filter = translated.Value;
        }

        if (query.Sort is { } sort && ScimSort.Canonical(sort.Attribute, ScimSort.Users) is null)
        {
            return Error.Failure(ScimErrors.InvalidValue, $"Users can be sorted by {string.Join(", ", ScimSort.Users)}.");
        }

        var (page, total) = await users.ListAsync(query.TenantId, filter, Math.Max(query.StartIndex, 1) - 1, Math.Clamp(query.Count, 0, 200),
            query.Sort is { } requested ? requested with { Attribute = ScimSort.Canonical(requested.Attribute, ScimSort.Users)! } : null, cancellationToken).ConfigureAwait(false);
        var views = new List<ScimUserView>(page.Count);
        foreach (var user in page)
        {
            views.Add(await provisioning.ViewAsync(user, cancellationToken).ConfigureAwait(false));
        }

        return new ScimPage<ScimUserView>(views, total, Math.Max(query.StartIndex, 1));
    }
}

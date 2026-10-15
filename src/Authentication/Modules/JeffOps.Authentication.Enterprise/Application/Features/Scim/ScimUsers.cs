using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Enterprise.Application.Features.Scim;

public sealed record ScimPage<T>(IReadOnlyList<T> Resources, int TotalResults, int StartIndex);

public sealed record CreateScimUserCommand(Guid TenantId, ScimUserData Data);

public sealed class CreateScimUserHandler(ScimProvisioning provisioning, IEnterpriseUnitOfWork unitOfWork) : ICommandHandler<CreateScimUserCommand, ScimUserView>
{
    public async Task<Result<ScimUserView>> HandleAsync(CreateScimUserCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
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
/// <see cref="UpdateScimUserCommand.Change"/>, so both paths run the same rules.
/// </summary>
public sealed record UpdateScimUserCommand(Guid TenantId, Guid UserId, Func<ScimUserData, Result<ScimUserData>> Change);

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

        var current = await provisioning.ViewAsync(user, cancellationToken).ConfigureAwait(false);
        var next = command.Change(new ScimUserData(user.UserName, user.ExternalId, user.GivenName, user.FamilyName, user.DisplayName, current.Email, user.Active));
        if (next.IsFailure)
        {
            return next.Error;
        }

        var applied = await provisioning.ApplyAsync(user, next.Value, cancellationToken).ConfigureAwait(false);
        if (applied.IsFailure)
        {
            return applied.Error;
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return await provisioning.ViewAsync(user, cancellationToken).ConfigureAwait(false);
    }
}

public sealed record DeleteScimUserCommand(Guid TenantId, Guid UserId);

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

        var failure = await provisioning.DeleteAsync(user, cancellationToken).ConfigureAwait(false);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return failure is null ? Result.Success() : failure;
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
public sealed record ListScimUsersQuery(Guid TenantId, ScimFilter? Filter, int StartIndex, int Count);

public sealed class ListScimUsersHandler(IScimUserRepository users, ScimProvisioning provisioning) : IQueryHandler<ListScimUsersQuery, ScimPage<ScimUserView>>
{
    public async Task<Result<ScimPage<ScimUserView>>> HandleAsync(ListScimUsersQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (query.Filter is { Attribute: var attribute } && attribute is not ("userName" or "externalId"))
        {
            return Error.Failure(ScimErrors.InvalidFilter, "Users can be filtered by userName or externalId (eq).");
        }

        var (page, total) = await users.ListAsync(query.TenantId, query.Filter, Math.Max(query.StartIndex, 1) - 1, Math.Clamp(query.Count, 0, 200), cancellationToken).ConfigureAwait(false);
        var views = new List<ScimUserView>(page.Count);
        foreach (var user in page)
        {
            views.Add(await provisioning.ViewAsync(user, cancellationToken).ConfigureAwait(false));
        }

        return new ScimPage<ScimUserView>(views, total, Math.Max(query.StartIndex, 1));
    }
}

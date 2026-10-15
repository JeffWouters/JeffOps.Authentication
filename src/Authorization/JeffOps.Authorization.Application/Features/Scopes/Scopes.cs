using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Application.Management;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Management;
using JeffOps.Authorization.Domain.Scopes;

namespace JeffOps.Authorization.Application.Features.Scopes;

internal static class ScopeMapping
{
    public static ScopeDto ToDto(this Scope scope) => new(scope.Id, scope.Name, scope.Description, scope.ParentKey, scope.IsBuiltIn);
}

public sealed record ListScopesQuery;

public sealed class ListScopesHandler(IScopeRepository scopes) : IQueryHandler<ListScopesQuery, IReadOnlyList<ScopeDto>>
{
    public async Task<Result<IReadOnlyList<ScopeDto>>> HandleAsync(ListScopesQuery query, CancellationToken cancellationToken) =>
        (await scopes.ListAsync(cancellationToken).ConfigureAwait(false)).Select(scope => scope.ToDto()).ToList();
}

/// <summary>Creates or updates a scope (platform administrators). Refuses cycles and changes to built-in scopes.</summary>
public sealed record UpsertScopeCommand(ManagementCaller Caller, UpsertScopeRequest Request, bool Create);

public sealed class UpsertScopeHandler(IScopeRepository scopes, IUnitOfWork unitOfWork, ManagementAudit audit) : ICommandHandler<UpsertScopeCommand, ScopeDto>
{
    public async Task<Result<ScopeDto>> HandleAsync(UpsertScopeCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (!command.Caller.IsRoot)
        {
            return Error.Forbidden(ManagementErrors.MissingPermission, "Only a platform administrator can change the scope hierarchy.");
        }

        var request = command.Request;
        if (string.IsNullOrWhiteSpace(request.Key) || string.IsNullOrWhiteSpace(request.Name))
        {
            return Error.Validation([new ValidationFailure(nameof(request.Key), "A key and a name are required.")]);
        }

        var key = Scope.Normalize(request.Key);
        var parent = request.ParentKey is null ? null : Scope.Normalize(request.ParentKey);
        var all = await scopes.ListAsync(cancellationToken).ConfigureAwait(false);
        var parentOf = all.ToDictionary(scope => scope.Id, scope => scope.ParentKey, StringComparer.Ordinal);
        var existing = all.FirstOrDefault(scope => scope.Id == key);

        if (parent is null || !parentOf.ContainsKey(parent))
        {
            return Error.Failure(ManagementErrors.InvalidScope, "Every scope needs an existing parent.");
        }

        Scope scope;
        if (command.Create)
        {
            if (existing is not null)
            {
                return Error.Conflict(ManagementErrors.Duplicate, $"Scope '{key}' already exists.");
            }

            scope = Scope.Create(key, request.Name, request.Description, parent);
            scopes.Add(scope);
        }
        else
        {
            if (existing is null)
            {
                return Error.NotFound(ManagementErrors.NotFound, "No such scope.");
            }

            if (existing.IsBuiltIn)
            {
                return Error.Forbidden(ManagementErrors.BuiltIn, "Built-in scopes can't be changed.");
            }

            if (ScopeHierarchy.WouldCycle(key, parent, parentOf))
            {
                return Error.Failure(ManagementErrors.Cycle, "That parent would put the scope inside itself.");
            }

            existing.Update(request.Name, request.Description, parent);
            scope = existing;
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync("scope.saved", "scope", key, command.Caller, null, cancellationToken).ConfigureAwait(false);
        return scope.ToDto();
    }
}

public sealed record DeleteScopeCommand(ManagementCaller Caller, string Key);

public sealed class DeleteScopeHandler(IScopeRepository scopes, IUnitOfWork unitOfWork, ManagementAudit audit) : ICommandHandler<DeleteScopeCommand>
{
    public async Task<Result> HandleAsync(DeleteScopeCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (!command.Caller.IsRoot)
        {
            return Error.Forbidden(ManagementErrors.MissingPermission, "Only a platform administrator can change the scope hierarchy.");
        }

        var key = Scope.Normalize(command.Key);
        var all = await scopes.ListAsync(cancellationToken).ConfigureAwait(false);
        var scope = all.FirstOrDefault(candidate => candidate.Id == key);
        if (scope is null)
        {
            return Error.NotFound(ManagementErrors.NotFound, "No such scope.");
        }

        if (scope.IsBuiltIn)
        {
            return Error.Forbidden(ManagementErrors.BuiltIn, "Built-in scopes can't be deleted.");
        }

        if (all.Any(candidate => candidate.ParentKey == key))
        {
            return Error.Conflict(ManagementErrors.ScopeInUse, "Delete or move the scope's children first.");
        }

        scope.Delete();
        scopes.Remove(scope);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync("scope.deleted", "scope", key, command.Caller, null, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.SharedKernel.Handlers;

/// <summary>
/// Handles a command that changes state and returns no value. One implementation per slice; endpoints inject the
/// interface directly. There is no mediator (docs/DESIGN.md §6.1).
/// </summary>
public interface ICommandHandler<in TCommand>
{
    Task<Result> HandleAsync(TCommand command, CancellationToken cancellationToken);
}

/// <summary>
/// Handles a command that changes state and returns a <typeparamref name="TResult"/>.
/// </summary>
public interface ICommandHandler<in TCommand, TResult>
{
    Task<Result<TResult>> HandleAsync(TCommand command, CancellationToken cancellationToken);
}

/// <summary>
/// Handles a query that reads state without changing it.
/// </summary>
public interface IQueryHandler<in TQuery, TResult>
{
    Task<Result<TResult>> HandleAsync(TQuery query, CancellationToken cancellationToken);
}

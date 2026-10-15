using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.SharedKernel.Validation;

/// <summary>
/// Decorators that run every registered <see cref="IValidator{T}"/> before the inner handler and short-circuit
/// with <see cref="Error.Validation"/> when any rule fails. Applied by
/// <see cref="DependencyInjection.HandlerServiceCollectionExtensions.AddHandlerValidation"/>.
/// </summary>
internal static class ValidationRunner
{
    public static List<ValidationFailure> Run<T>(IEnumerable<IValidator<T>> validators, T instance) =>
        validators.SelectMany(validator => validator.Validate(instance)).ToList();
}

internal sealed class ValidatingCommandHandler<TCommand>(
    ICommandHandler<TCommand> inner,
    IEnumerable<IValidator<TCommand>> validators) : ICommandHandler<TCommand>
{
    public Task<Result> HandleAsync(TCommand command, CancellationToken cancellationToken)
    {
        var failures = ValidationRunner.Run(validators, command);
        return failures.Count == 0
            ? inner.HandleAsync(command, cancellationToken)
            : Task.FromResult(Result.Failure(Error.Validation(failures)));
    }
}

internal sealed class ValidatingCommandHandler<TCommand, TResult>(
    ICommandHandler<TCommand, TResult> inner,
    IEnumerable<IValidator<TCommand>> validators) : ICommandHandler<TCommand, TResult>
{
    public Task<Result<TResult>> HandleAsync(TCommand command, CancellationToken cancellationToken)
    {
        var failures = ValidationRunner.Run(validators, command);
        return failures.Count == 0
            ? inner.HandleAsync(command, cancellationToken)
            : Task.FromResult(Result.Failure<TResult>(Error.Validation(failures)));
    }
}

internal sealed class ValidatingQueryHandler<TQuery, TResult>(
    IQueryHandler<TQuery, TResult> inner,
    IEnumerable<IValidator<TQuery>> validators) : IQueryHandler<TQuery, TResult>
{
    public Task<Result<TResult>> HandleAsync(TQuery query, CancellationToken cancellationToken)
    {
        var failures = ValidationRunner.Run(validators, query);
        return failures.Count == 0
            ? inner.HandleAsync(query, cancellationToken)
            : Task.FromResult(Result.Failure<TResult>(Error.Validation(failures)));
    }
}

using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.SharedKernel.Validation;

/// <summary>
/// Validates a command or query before its handler runs, for rules that DataAnnotations can't express.
/// Validators are synchronous and side-effect free; rules that need I/O belong in the handler.
/// </summary>
public interface IValidator<in T>
{
    IEnumerable<ValidationFailure> Validate(T instance);
}

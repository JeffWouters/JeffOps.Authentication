namespace JeffOps.Authentication.SharedKernel.Results;

/// <summary>
/// Category of an expected failure. Endpoints map it to an HTTP status code (docs/DESIGN.md §6.1).
/// </summary>
public enum ErrorType
{
    /// <summary>Generic failure; maps to 400.</summary>
    Failure,

    /// <summary>Input failed validation; maps to 400 with a list of failures.</summary>
    Validation,

    /// <summary>Caller is not authenticated; maps to 401.</summary>
    Unauthorized,

    /// <summary>Caller is not entitled (licensing); maps to 402.</summary>
    PaymentRequired,

    /// <summary>Caller is authenticated but not allowed; maps to 403.</summary>
    Forbidden,

    /// <summary>Target does not exist (or must not be revealed); maps to 404.</summary>
    NotFound,

    /// <summary>State conflict, e.g. a concurrent update; maps to 409.</summary>
    Conflict,

    /// <summary>A dependency is unavailable and the caller should retry; maps to 503.</summary>
    Unavailable,
}

/// <summary>
/// A single input validation failure.
/// </summary>
/// <param name="Property">Name of the offending input member.</param>
/// <param name="Message">Human-readable reason.</param>
public sealed record ValidationFailure(string Property, string Message);

/// <summary>
/// An expected failure. <see cref="Code"/> is a stable, machine-readable identifier (for example
/// <c>step_up_required</c>) that clients may switch on; <see cref="Message"/> is for humans.
/// </summary>
public sealed record Error
{
    /// <summary>The absence of an error; only carried by successful results.</summary>
    public static readonly Error None = new(string.Empty, string.Empty, ErrorType.Failure);

    /// <summary>Creates an error; the factory methods such as <see cref="NotFound"/> are usually shorter.</summary>
    public Error(string code, string message, ErrorType type, IReadOnlyList<ValidationFailure>? failures = null)
    {
        Code = code;
        Message = message;
        Type = type;
        Failures = failures ?? [];
    }

    /// <summary>Stable, machine-readable identifier, returned to clients as the ProblemDetails <c>code</c> extension.</summary>
    public string Code { get; }

    /// <summary>Human-readable description of the failure.</summary>
    public string Message { get; }

    /// <summary>The failure category, which decides the HTTP status code.</summary>
    public ErrorType Type { get; }

    /// <summary>Validation failures; empty unless <see cref="Type"/> is <see cref="ErrorType.Validation"/>.</summary>
    public IReadOnlyList<ValidationFailure> Failures { get; }

    /// <summary>Creates a generic failure (400).</summary>
    public static Error Failure(string code, string message) => new(code, message, ErrorType.Failure);

    /// <summary>Creates an error for an unauthenticated caller (401).</summary>
    public static Error Unauthorized(string code, string message) => new(code, message, ErrorType.Unauthorized);

    /// <summary>Creates an error for a caller not entitled to the feature by its licence (402).</summary>
    public static Error PaymentRequired(string code, string message) => new(code, message, ErrorType.PaymentRequired);

    /// <summary>Creates an error for an authenticated caller that is not allowed (403).</summary>
    public static Error Forbidden(string code, string message) => new(code, message, ErrorType.Forbidden);

    /// <summary>Creates an error for a target that does not exist or must not be revealed (404).</summary>
    public static Error NotFound(string code, string message) => new(code, message, ErrorType.NotFound);

    /// <summary>Creates an error for a state conflict, such as a concurrent update (409).</summary>
    public static Error Conflict(string code, string message) => new(code, message, ErrorType.Conflict);

    /// <summary>Creates an error for an unavailable dependency; the caller should retry (503).</summary>
    public static Error Unavailable(string code, string message) => new(code, message, ErrorType.Unavailable);

    /// <summary>Creates a validation error (400) with code <c>validation_failed</c> that carries <paramref name="failures"/>.</summary>
    public static Error Validation(IReadOnlyList<ValidationFailure> failures) =>
        new("validation_failed", "One or more validation errors occurred.", ErrorType.Validation, failures);
}

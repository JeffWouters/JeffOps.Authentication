namespace JeffOps.Authentication.SharedKernel.Results;

/// <summary>
/// Outcome of an operation without a value. Expected failures are returned, never thrown (docs/DESIGN.md §6.1).
/// </summary>
public class Result
{
    /// <summary>Creates a result; a success must carry <see cref="Error.None"/> and a failure must not.</summary>
    /// <exception cref="ArgumentException"><paramref name="error"/> does not match <paramref name="isSuccess"/>.</exception>
    protected Result(bool isSuccess, Error error)
    {
        if (isSuccess && error != Error.None)
        {
            throw new ArgumentException("A successful result cannot carry an error.", nameof(error));
        }

        if (!isSuccess && error == Error.None)
        {
            throw new ArgumentException("A failed result must carry an error.", nameof(error));
        }

        IsSuccess = isSuccess;
        Error = error;
    }

    /// <summary>Whether the operation succeeded.</summary>
    public bool IsSuccess { get; }

    /// <summary>Whether the operation failed; the opposite of <see cref="IsSuccess"/>.</summary>
    public bool IsFailure => !IsSuccess;

    /// <summary>The failure; <see cref="Error.None"/> when <see cref="IsSuccess"/> is true.</summary>
    public Error Error { get; }

    /// <summary>Creates a successful result.</summary>
    public static Result Success() => new(true, Error.None);

    /// <summary>Creates a failed result carrying <paramref name="error"/>.</summary>
    public static Result Failure(Error error) => new(false, error);

    /// <summary>Creates a successful result carrying <paramref name="value"/>.</summary>
    public static Result<TValue> Success<TValue>(TValue value) => new(value);

    /// <summary>Creates a failed result of <typeparamref name="TValue"/> carrying <paramref name="error"/>.</summary>
    public static Result<TValue> Failure<TValue>(Error error) => new(error);

    /// <summary>Converts an error to a failed result, so a handler can <c>return error;</c>.</summary>
    public static implicit operator Result(Error error) => Failure(error);
}

/// <summary>
/// Outcome of an operation that produces a <typeparamref name="TValue"/> on success.
/// </summary>
public sealed class Result<TValue> : Result
{
    private readonly TValue? _value;

    internal Result(TValue value)
        : base(true, Error.None) => _value = value;

    internal Result(Error error)
        : base(false, error)
    {
    }

    /// <summary>The value of a successful result.</summary>
    /// <exception cref="InvalidOperationException">The result is a failure.</exception>
    public TValue Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException("Cannot read the value of a failed result; check IsSuccess first.");

    /// <summary>Applies <paramref name="onSuccess"/> to the value or <paramref name="onFailure"/> to the error, and returns what it produces.</summary>
    public TOut Match<TOut>(Func<TValue, TOut> onSuccess, Func<Error, TOut> onFailure)
    {
        ArgumentNullException.ThrowIfNull(onSuccess);
        ArgumentNullException.ThrowIfNull(onFailure);
        return IsSuccess ? onSuccess(_value!) : onFailure(Error);
    }

    /// <summary>Converts a value to a successful result, so a handler can <c>return value;</c>.</summary>
    public static implicit operator Result<TValue>(TValue value) => new(value);

    /// <summary>Converts an error to a failed result, so a handler can <c>return error;</c>.</summary>
    public static implicit operator Result<TValue>(Error error) => new(error);
}

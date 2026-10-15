using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authentication.Endpoints.Http;

/// <summary>Maps <see cref="Result"/> failures to RFC 9457 problem details with a <c>code</c> extension (docs/DESIGN.md §6.1).</summary>
internal static class ResultMapping
{
    public static IResult ToProblem(this Error error)
    {
        ArgumentNullException.ThrowIfNull(error);

        var extensions = new Dictionary<string, object?> { ["code"] = error.Code };
        if (error.Type == ErrorType.Validation)
        {
            return TypedResults.ValidationProblem(
                error.Failures.GroupBy(failure => failure.Property).ToDictionary(group => group.Key, group => group.Select(failure => failure.Message).ToArray()),
                detail: error.Message,
                extensions: extensions);
        }

        return TypedResults.Problem(detail: error.Message, statusCode: StatusOf(error.Type), extensions: extensions);
    }

    public static IResult ToHttpResult(this Result result, Func<IResult>? onSuccess = null) =>
        result.IsSuccess ? onSuccess?.Invoke() ?? TypedResults.NoContent() : result.Error.ToProblem();

    public static IResult ToHttpResult<T>(this Result<T> result, Func<T, IResult> onSuccess) =>
        result.IsSuccess ? onSuccess(result.Value) : result.Error.ToProblem();

    public static int StatusOf(ErrorType type) => type switch
    {
        ErrorType.Validation => StatusCodes.Status400BadRequest,
        ErrorType.Unauthorized => StatusCodes.Status401Unauthorized,
        ErrorType.PaymentRequired => StatusCodes.Status402PaymentRequired,
        ErrorType.Forbidden => StatusCodes.Status403Forbidden,
        ErrorType.NotFound => StatusCodes.Status404NotFound,
        ErrorType.Conflict => StatusCodes.Status409Conflict,
        ErrorType.Unavailable => StatusCodes.Status503ServiceUnavailable,
        _ => StatusCodes.Status400BadRequest,
    };
}

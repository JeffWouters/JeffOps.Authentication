using JeffOps.Authorization.Domain.Ceilings;
using JeffOps.Authorization.Domain.Decisions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace JeffOps.Authorization.AspNetCore.Evaluation;

/// <summary>
/// Answers refusals a client can act on with RFC 9457 problem details carrying a <c>code</c>:
/// <list type="bullet">
/// <item><c>step_up_required</c>: 403 plus <c>WWW-Authenticate: Bearer error="insufficient_user_authentication"</c>
/// (RFC 9470), so the client can send the user to sign in with multi-factor authentication.</item>
/// <item><c>impersonation_not_allowed</c>: 403; signing in again won't help, ending the impersonation will.</item>
/// </list>
/// Every other outcome goes to the default handler unchanged.
/// </summary>
internal sealed class PermissionResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _default = new();

    public Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(authorizeResult);

        if (authorizeResult.Forbidden && HasReason(authorizeResult, AuthorizationCodes.StepUpRequired))
        {
            context.Response.Headers.WWWAuthenticate =
                "Bearer error=\"insufficient_user_authentication\", error_description=\"A multi-factor sign-in is required.\"";
            return Problem(
                AuthorizationCodes.StepUpRequired,
                "Step-up required",
                "This action requires a multi-factor sign-in. Sign in again using multi-factor authentication.").ExecuteAsync(context);
        }

        if (authorizeResult.Forbidden && HasReason(authorizeResult, AuthorizationCodes.ImpersonationNotAllowed))
        {
            return Problem(
                AuthorizationCodes.ImpersonationNotAllowed,
                "Not available while impersonating",
                "This change is not available while impersonating another user. End the impersonation and use your own session.").ExecuteAsync(context);
        }

        return _default.HandleAsync(next, context, policy, authorizeResult);
    }

    private static bool HasReason(PolicyAuthorizationResult result, string code) =>
        result.AuthorizationFailure?.FailureReasons.Any(reason => reason.Message == code) == true;

    private static IResult Problem(string code, string title, string detail) =>
        TypedResults.Problem(
            detail: detail,
            statusCode: StatusCodes.Status403Forbidden,
            title: title,
            extensions: new Dictionary<string, object?> { ["code"] = code });
}

/// <summary>
/// Validates route rules when the host starts: a step-up exemption naming a permission that isn't sensitive does nothing,
/// so it is a typo or a stale rename that leaves the intended route gated. Fails startup instead.
/// </summary>
/// <remarks>
/// A startup filter rather than a hosted service: the web server's hosted service starts last, and minimal API endpoints
/// only reach the shared endpoint data source while it builds the request pipeline. Validating right after the rest of the
/// pipeline is built sees every endpoint, and an exception here fails <c>StartAsync</c>.
/// </remarks>
internal sealed class RouteRuleValidator(IOptions<PermissionAuthorizationOptions> options) : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        next(app);
        Validate(app.ApplicationServices.GetRequiredService<EndpointDataSource>(), options.Value);
    };

    internal static void Validate(EndpointDataSource endpoints, PermissionAuthorizationOptions options)
    {
        var policy = new StepUpPolicy([.. options.SensitivePermissions]);

        var problems = (
            from endpoint in endpoints.Endpoints
            from rule in endpoint.Metadata.GetOrderedMetadata<StepUpRouteRule>()
            where !rule.Required
            from permission in rule.Permissions
            where !policy.IsSensitive(permission)
            select $"'{endpoint.DisplayName}' exempts '{permission}' from step-up, but it is not a sensitive permission").ToList();

        if (problems.Count > 0)
        {
            throw new InvalidOperationException(
                "Invalid step-up exemptions (configure JeffOps:Authorization:SensitivePermissions or remove the exemption): "
                + string.Join("; ", problems));
        }
    }
}

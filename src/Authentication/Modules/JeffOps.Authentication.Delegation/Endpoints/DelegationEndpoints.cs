using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Delegation.Application;
using JeffOps.Authentication.Delegation.Application.Features.Impersonation;
using JeffOps.Authentication.Delegation.Application.Features.TenantAccess;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Validation.AspNetCore;

namespace JeffOps.Authentication.Delegation.Endpoints;

public sealed record RequestImpersonationRequest(Guid TargetUserId, bool BreakGlass = false, string? Reason = null);

public sealed record RequestTenantAccessRequest(Guid TenantId);

public static class DelegationEndpointRouteBuilderExtensions
{
    public const string ImpersonationRoutes = "delegation/impersonation";
    public const string TenantAccessRoutes = "delegation/tenant-access";

    /// <summary>
    /// Maps the delegation API, for users holding an access token of this server:
    /// <list type="bullet">
    /// <item><c>delegation/impersonation</c>: request (actor), approve/deny (target), end/revoke (either side), get, list.</item>
    /// <item><c>delegation/tenant-access</c>: request (partner user), approve/deny/revoke (tenant administrator), end, list.</item>
    /// </list>
    /// Tokens are minted at <c>connect/token</c> with the extension grants <c>impersonation</c> and <c>tenant-switch</c>.
    /// </summary>
    public static IEndpointRouteBuilder MapJeffOpsDelegation(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var tokenPolicy = new AuthorizationPolicyBuilder(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme).RequireAuthenticatedUser().Build();

        var impersonation = endpoints.MapGroup(ImpersonationRoutes).WithTags("Impersonation").RequireAuthorization(tokenPolicy);
        impersonation.MapPost("/", RequestImpersonationAsync).AddEndpointFilter<StepUpFilter>().WithName("RequestImpersonation");
        impersonation.MapGet("/", ListImpersonationsAsync).WithName("ListImpersonations");
        impersonation.MapGet("/{grantId:guid}", GetImpersonationAsync).WithName("GetImpersonation");
        impersonation.MapPost("/{grantId:guid}/approve", (Guid grantId, HttpContext context, ICommandHandler<DecideImpersonationCommand, ImpersonationGrantDto> handler) =>
            DecideImpersonationAsync(grantId, approve: true, context, handler)).AddEndpointFilter<StepUpFilter>().WithName("ApproveImpersonation");
        impersonation.MapPost("/{grantId:guid}/deny", (Guid grantId, HttpContext context, ICommandHandler<DecideImpersonationCommand, ImpersonationGrantDto> handler) =>
            DecideImpersonationAsync(grantId, approve: false, context, handler)).WithName("DenyImpersonation");
        impersonation.MapPost("/{grantId:guid}/end", (Guid grantId, HttpContext context, ICommandHandler<EndImpersonationCommand, ImpersonationGrantDto> handler) =>
            EndImpersonationAsync(grantId, revoke: false, context, handler)).WithName("EndImpersonation");
        impersonation.MapPost("/{grantId:guid}/revoke", (Guid grantId, HttpContext context, ICommandHandler<EndImpersonationCommand, ImpersonationGrantDto> handler) =>
            EndImpersonationAsync(grantId, revoke: true, context, handler)).WithName("RevokeImpersonation");

        var access = endpoints.MapGroup(TenantAccessRoutes).WithTags("Tenant access").RequireAuthorization(tokenPolicy);
        access.MapPost("/", RequestTenantAccessAsync).AddEndpointFilter<StepUpFilter>().WithName("RequestTenantAccess");
        access.MapGet("/", ListTenantAccessAsync).WithName("ListTenantAccess");
        access.MapPost("/{grantId:guid}/approve", (Guid grantId, HttpContext context, ICommandHandler<DecideTenantAccessCommand, TenantAccessGrantDto> handler) =>
            DecideTenantAccessAsync(grantId, approve: true, context, handler)).AddEndpointFilter<StepUpFilter>().WithName("ApproveTenantAccess");
        access.MapPost("/{grantId:guid}/deny", (Guid grantId, HttpContext context, ICommandHandler<DecideTenantAccessCommand, TenantAccessGrantDto> handler) =>
            DecideTenantAccessAsync(grantId, approve: false, context, handler)).WithName("DenyTenantAccess");
        access.MapPost("/{grantId:guid}/end", (Guid grantId, HttpContext context, ICommandHandler<EndTenantAccessCommand, TenantAccessGrantDto> handler) =>
            EndTenantAccessAsync(grantId, revoke: false, context, handler)).WithName("EndTenantAccess");
        access.MapPost("/{grantId:guid}/revoke", (Guid grantId, HttpContext context, ICommandHandler<EndTenantAccessCommand, TenantAccessGrantDto> handler) =>
            EndTenantAccessAsync(grantId, revoke: true, context, handler)).WithName("RevokeTenantAccess");

        return endpoints;
    }

    // ---- Impersonation -------------------------------------------------------------------------------------------------

    private static async Task<IResult> RequestImpersonationAsync(
        RequestImpersonationRequest request,
        HttpContext context,
        ICommandHandler<RequestImpersonationCommand, ImpersonationGrantDto> handler,
        IOptions<DelegationOptions> options)
    {
        if (Caller(context) is not { } caller)
        {
            return TypedResults.Forbid();
        }

        var settings = options.Value.Impersonation;
        var mayInitiate = await PassesAsync(context, settings.InitiatePolicy).ConfigureAwait(false);
        var mayBreakGlass = request.BreakGlass && await PassesAsync(context, settings.BreakGlassPolicy).ConfigureAwait(false);

        var result = await handler.HandleAsync(
            new RequestImpersonationCommand(caller, request.TargetUserId, request.BreakGlass, request.Reason, mayInitiate, mayBreakGlass),
            context.RequestAborted).ConfigureAwait(false);
        return result.IsSuccess ? TypedResults.Ok(result.Value) : Problem(result.Error);
    }

    private static async Task<IResult> ListImpersonationsAsync(HttpContext context, IQueryHandler<ListImpersonationsQuery, ImpersonationOverview> handler)
    {
        if (UserIdOf(context) is not { } userId)
        {
            return TypedResults.Forbid();
        }

        return ToResult(await handler.HandleAsync(new ListImpersonationsQuery(userId), context.RequestAborted).ConfigureAwait(false));
    }

    private static async Task<IResult> GetImpersonationAsync(Guid grantId, HttpContext context, IQueryHandler<GetImpersonationQuery, ImpersonationGrantDto> handler)
    {
        if (UserIdOf(context) is not { } userId)
        {
            return TypedResults.Forbid();
        }

        return ToResult(await handler.HandleAsync(new GetImpersonationQuery(userId, grantId), context.RequestAborted).ConfigureAwait(false));
    }

    private static async Task<IResult> DecideImpersonationAsync(Guid grantId, bool approve, HttpContext context, ICommandHandler<DecideImpersonationCommand, ImpersonationGrantDto> handler)
    {
        if (Caller(context) is not { } caller)
        {
            return TypedResults.Forbid();
        }

        return ToResult(await handler.HandleAsync(new DecideImpersonationCommand(caller, grantId, approve), context.RequestAborted).ConfigureAwait(false));
    }

    private static async Task<IResult> EndImpersonationAsync(Guid grantId, bool revoke, HttpContext context, ICommandHandler<EndImpersonationCommand, ImpersonationGrantDto> handler)
    {
        // The actor's own session or the impersonation session (whose subject is the target, with the actor in "act") may end it.
        var userId = ActorOf(context) ?? UserIdOf(context);
        if (userId is not { } caller)
        {
            return TypedResults.Forbid();
        }

        return ToResult(await handler.HandleAsync(new EndImpersonationCommand(caller, grantId, revoke), context.RequestAborted).ConfigureAwait(false));
    }

    // ---- Tenant access -------------------------------------------------------------------------------------------------

    private static async Task<IResult> RequestTenantAccessAsync(RequestTenantAccessRequest request, HttpContext context, ICommandHandler<RequestTenantAccessCommand, TenantAccessGrantDto> handler)
    {
        if (Caller(context) is not { } caller)
        {
            return TypedResults.Forbid();
        }

        return ToResult(await handler.HandleAsync(new RequestTenantAccessCommand(caller, request.TenantId), context.RequestAborted).ConfigureAwait(false));
    }

    private static async Task<IResult> ListTenantAccessAsync(HttpContext context, IQueryHandler<ListTenantAccessQuery, TenantAccessOverview> handler, IOptions<DelegationOptions> options)
    {
        if (Caller(context) is not { } caller)
        {
            return TypedResults.Forbid();
        }

        var mayApprove = await PassesAsync(context, options.Value.TenantAccess.ApprovePolicy).ConfigureAwait(false);
        return ToResult(await handler.HandleAsync(new ListTenantAccessQuery(caller, mayApprove), context.RequestAborted).ConfigureAwait(false));
    }

    private static async Task<IResult> DecideTenantAccessAsync(Guid grantId, bool approve, HttpContext context, ICommandHandler<DecideTenantAccessCommand, TenantAccessGrantDto> handler)
    {
        if (Caller(context) is not { } caller)
        {
            return TypedResults.Forbid();
        }

        var mayApprove = await PassesAsync(context, context.RequestServices.GetRequiredService<IOptions<DelegationOptions>>().Value.TenantAccess.ApprovePolicy).ConfigureAwait(false);
        return ToResult(await handler.HandleAsync(new DecideTenantAccessCommand(caller, grantId, approve, mayApprove), context.RequestAborted).ConfigureAwait(false));
    }

    private static async Task<IResult> EndTenantAccessAsync(Guid grantId, bool revoke, HttpContext context, ICommandHandler<EndTenantAccessCommand, TenantAccessGrantDto> handler)
    {
        if (Caller(context) is not { } caller)
        {
            return TypedResults.Forbid();
        }

        var mayApprove = caller.IsHomeSession
            && await PassesAsync(context, context.RequestServices.GetRequiredService<IOptions<DelegationOptions>>().Value.TenantAccess.ApprovePolicy).ConfigureAwait(false);
        return ToResult(await handler.HandleAsync(new EndTenantAccessCommand(caller, grantId, revoke, mayApprove), context.RequestAborted).ConfigureAwait(false));
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private static ClaimNames Names(HttpContext context) => context.RequestServices.GetService<ClaimNames>() ?? ClaimNames.Default;

    private static DelegationCaller? Caller(HttpContext context) => DelegationCaller.From(context.User, Names(context));

    private static Guid? UserIdOf(HttpContext context) => Caller(context)?.UserId;

    /// <summary>The acting user of an impersonation token, from its RFC 8693 <c>act</c> claim.</summary>
    private static Guid? ActorOf(HttpContext context)
    {
        var act = context.User.FindFirst(Names(context).Actor)?.Value;
        if (string.IsNullOrEmpty(act))
        {
            return null;
        }

        try
        {
            using var document = System.Text.Json.JsonDocument.Parse(act);
            return document.RootElement.TryGetProperty("sub", out var sub) && Guid.TryParse(sub.GetString(), out var actor) ? actor : null;
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
    }

    private static async Task<bool> PassesAsync(HttpContext context, string policy) =>
        (await context.RequestServices.GetRequiredService<IAuthorizationService>().AuthorizeAsync(context.User, policy).ConfigureAwait(false)).Succeeded;

    private static IResult ToResult<T>(Result<T> result) => result.IsSuccess ? TypedResults.Ok(result.Value) : Problem(result.Error);

    private static IResult Problem(Error error) =>
        TypedResults.Problem(
            detail: error.Message,
            statusCode: error.Type switch
            {
                ErrorType.Forbidden => StatusCodes.Status403Forbidden,
                ErrorType.NotFound => StatusCodes.Status404NotFound,
                ErrorType.Conflict => StatusCodes.Status409Conflict,
                ErrorType.Unauthorized => StatusCodes.Status401Unauthorized,
                ErrorType.Unavailable => StatusCodes.Status503ServiceUnavailable,
                _ => StatusCodes.Status400BadRequest,
            },
            extensions: new Dictionary<string, object?> { ["code"] = error.Code });
}

/// <summary>Requesting and approving delegated access needs a stepped-up sign-in (RFC 9470 challenge), unless turned off.</summary>
internal sealed class StepUpFilter : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var http = context.HttpContext;
        var names = http.RequestServices.GetService<ClaimNames>() ?? ClaimNames.Default;
        if (!http.RequestServices.GetRequiredService<IOptions<DelegationOptions>>().Value.RequireStepUp || AccessContextReader.IsSteppedUp(http.User, names))
        {
            return next(context);
        }

        http.Response.Headers.WWWAuthenticate =
            "Bearer error=\"insufficient_user_authentication\", error_description=\"A multi-factor sign-in is required.\"";
        return ValueTask.FromResult<object?>(TypedResults.Problem(
            detail: "Delegated access requires a multi-factor sign-in (step-up).",
            statusCode: StatusCodes.Status403Forbidden,
            extensions: new Dictionary<string, object?> { ["code"] = "step_up_required" }));
    }
}

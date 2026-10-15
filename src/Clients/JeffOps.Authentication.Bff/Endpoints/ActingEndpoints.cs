using JeffOps.Authentication.Bff.Middleware;
using JeffOps.Authentication.Bff.Sessions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;

namespace JeffOps.Authentication.Bff.Endpoints;

/// <summary>
/// Starting, inspecting and stopping derived sessions. Requests and approvals go to the token server's delegation API through
/// the proxy like any other API call; these endpoints only turn an approved grant (or a managed tenant) into a session.
/// </summary>
internal static partial class ActingEndpoints
{
    public const string AuthorityClient = "JeffOps.Bff.Authority";

    public static void Map(IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup(string.Empty).ExcludeFromDescription().AllowAnonymous();
        group.MapGet(BffPaths.Acting, CurrentAsync);
        group.MapPost(BffPaths.StartImpersonation, (string grantId, HttpContext context, DerivedSessionManager derived, IOptions<BffOptions> options) =>
            StartAsync(context, derived, options.Value, (owner, cancellationToken) => derived.StartImpersonationAsync(owner, grantId, cancellationToken)));
        group.MapPost(BffPaths.SwitchTenant, (Guid tenantId, HttpContext context, DerivedSessionManager derived, IOptions<BffOptions> options) =>
            StartAsync(context, derived, options.Value, (owner, cancellationToken) => derived.StartTenantSwitchAsync(owner, tenantId.ToString(), cancellationToken)));
        group.MapPost(BffPaths.StopActing, StopAsync);
    }

    /// <summary>What the browser is acting as: <c>{ acting: null }</c>, or the kind, grant or tenant, and the acting user's claims.</summary>
    private static async Task<IResult> CurrentAsync(HttpContext context, DerivedSessionManager derived, IOptions<BffOptions> options)
    {
        var settings = options.Value;
        if (OwnerId(context, settings) is not { } owner)
        {
            return TypedResults.Unauthorized();
        }

        if (!context.Request.Cookies.TryGetValue(BffCookie.ActingName(context.Request, settings), out var id) || string.IsNullOrEmpty(id)
            || await derived.GetFreshAsync(id, owner, context.RequestAborted).ConfigureAwait(false) is not { } session)
        {
            return TypedResults.Ok(new { acting = (string?)null });
        }

        return TypedResults.Ok(new
        {
            acting = session.Kind,
            grantId = session.GrantId,
            tenantId = session.ActingTenantId,
            endsAt = session.SessionEndsAt,
            user = Claims(session.AccessToken, settings),
        });
    }

    private static async Task<IResult> StartAsync(
        HttpContext context,
        DerivedSessionManager derived,
        BffOptions settings,
        Func<string, CancellationToken, Task<DerivedStart>> start)
    {
        if (OwnerId(context, settings) is not { } owner)
        {
            return TypedResults.Unauthorized();
        }

        DerivedStart started;
        try
        {
            started = await start(owner, context.RequestAborted).ConfigureAwait(false);
        }
        catch (SessionStoreUnavailableException)
        {
            started = new DerivedStart(DerivedOutcome.Unavailable);
        }

        switch (started.Outcome)
        {
            case DerivedOutcome.Started:
                var cookie = BffCookie.ActingName(context.Request, settings);
                if (context.Request.Cookies.TryGetValue(cookie, out var previous) && !string.IsNullOrEmpty(previous))
                {
                    await derived.EndAsync(previous, context.RequestAborted).ConfigureAwait(false);
                }

                context.Response.Cookies.Append(cookie, started.Id!, BffCookie.Options(context.Request, started.Session!.SessionEndsAt));
                return TypedResults.Ok(new
                {
                    acting = started.Session.Kind,
                    grantId = started.Session.GrantId,
                    tenantId = started.Session.ActingTenantId,
                    endsAt = started.Session.SessionEndsAt,
                    user = Claims(started.Session.AccessToken, settings),
                });
            case DerivedOutcome.SignedOut:
                return TypedResults.Unauthorized();
            case DerivedOutcome.Unavailable:
                return Problem(StatusCodes.Status503ServiceUnavailable, "unavailable", "The token server is unavailable. Try again shortly.");
            default:
                return Problem(StatusCodes.Status400BadRequest, "acting_refused", "The token server refused: the grant isn't approved or is over, or the tenant isn't available to you.");
        }
    }

    /// <summary>Stops acting: ends an impersonation grant at the token server (best effort) and deletes the derived session.</summary>
    private static async Task<IResult> StopAsync(
        HttpContext context,
        DerivedSessionManager derived,
        BffSessionManager sessions,
        IHttpClientFactory http,
        IOptions<BffOptions> options,
        ILoggerFactory loggers)
    {
        var settings = options.Value;
        var cookie = BffCookie.ActingName(context.Request, settings);
        if (context.Request.Cookies.TryGetValue(cookie, out var id) && !string.IsNullOrEmpty(id))
        {
            var session = await derived.EndAsync(id, context.RequestAborted).ConfigureAwait(false);
            if (session is { Kind: DerivedSessionManager.Impersonation, GrantId: { } grantId } && OwnerId(context, settings) is { } owner
                && DerivedSessionManager.BelongsTo(session, owner)
                && await sessions.GetFreshAsync(owner, readOnlyRequest: false, context.RequestAborted).ConfigureAwait(false) is { } own)
            {
                await EndGrantAsync(http, settings, grantId, own.AccessToken, loggers.CreateLogger("JeffOps.Authentication.Bff.Acting"), context.RequestAborted).ConfigureAwait(false);
            }
        }

        context.Response.Cookies.Delete(cookie, BffCookie.Options(context.Request, DateTimeOffset.UnixEpoch));
        return TypedResults.Ok(new { acting = (string?)null });
    }

    /// <summary>Ends the impersonation grant at the token server, so the target sees it end too. Best effort.</summary>
    internal static async Task EndGrantAsync(IHttpClientFactory http, BffOptions settings, string grantId, string accessToken, ILogger logger, CancellationToken cancellationToken)
    {
        try
        {
            using var client = http.CreateClient(AuthorityClient);
            using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(settings.Authority!, string.Format(System.Globalization.CultureInfo.InvariantCulture, settings.Delegation.EndImpersonationPath, Uri.EscapeDataString(grantId))));
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
            using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // Best effort: the derived session is gone either way and the grant expires.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogEndFailed(logger, exception);
        }
    }

    private static string? OwnerId(HttpContext context, BffOptions settings) =>
        context.Request.Cookies.TryGetValue(BffCookie.Name(context.Request, settings), out var id) && !string.IsNullOrEmpty(id) ? id : null;

    private static Dictionary<string, object> Claims(string accessToken, BffOptions settings)
    {
        var wanted = settings.UserClaims.ToHashSet(StringComparer.Ordinal);
        return new JsonWebToken(accessToken).Claims
            .Where(claim => wanted.Contains(claim.Type))
            .GroupBy(claim => claim.Type)
            .ToDictionary(group => group.Key, group => group.Count() == 1 ? (object)group.First().Value : group.Select(claim => claim.Value).ToArray());
    }

    private static IResult Problem(int status, string code, string detail) =>
        TypedResults.Problem(detail: detail, statusCode: status, extensions: new Dictionary<string, object?> { ["code"] = code });

    [LoggerMessage(EventId = 9131, Level = LogLevel.Warning, Message = "Ending an impersonation grant at the token server failed; it expires on its own.")]
    private static partial void LogEndFailed(ILogger logger, Exception exception);
}

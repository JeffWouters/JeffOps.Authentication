using JeffOps.Authentication.Bff.Sessions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Bff.Middleware;

/// <summary>The session cookie: <c>__Host-</c> prefixed on HTTPS, HttpOnly, SameSite=Lax.</summary>
public static class BffCookie
{
    /// <summary>The session cookie's name: <see cref="BffOptions.CookieName"/>, with a <c>__Host-</c> prefix on HTTPS.</summary>
    public static string Name(HttpRequest request, BffOptions options)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);
        return request.IsHttps ? "__Host-" + options.CookieName : options.CookieName;
    }

    /// <summary>The derived ("acting") session cookie.</summary>
    public static string ActingName(HttpRequest request, BffOptions options)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(options);
        return request.IsHttps ? "__Host-" + options.Delegation.CookieName : options.Delegation.CookieName;
    }

    /// <summary>
    /// Options for a BFF cookie expiring at <paramref name="expires"/>: HttpOnly, SameSite=Lax, path <c>/</c>, and Secure on
    /// HTTPS. Pass <see cref="DateTimeOffset.UnixEpoch"/> when deleting the cookie.
    /// </summary>
    public static CookieOptions Options(HttpRequest request, DateTimeOffset expires)
    {
        ArgumentNullException.ThrowIfNull(request);
        return new CookieOptions
        {
            HttpOnly = true,
            Secure = request.IsHttps,
            SameSite = SameSiteMode.Lax,
            Path = "/",
            Expires = expires,
            IsEssential = true,
        };
    }
}

/// <summary>
/// CSRF protection: a state-changing request that carries the session cookie, or targets <c>/bff/*</c>, must send the CSRF
/// header. A cross-site form or image can't add custom headers, and a cross-site fetch that adds one needs a CORS preflight
/// the BFF doesn't grant (docs/DESIGN.md §16). The back-channel logout endpoint is exempt: the token server calls it, not a
/// browser. A WebSocket handshake can't carry the header, so one with the session cookie must come from the BFF's own origin
/// or one of <see cref="BffOptions.WebSocketOrigins"/>.
/// </summary>
public sealed class CsrfMiddleware(RequestDelegate next, IOptions<BffOptions> options)
{
    /// <summary>
    /// Answers 403 with problem details to a state-changing request missing the CSRF header, or to a cookie-authenticated
    /// WebSocket handshake from another origin; otherwise calls the next middleware.
    /// </summary>
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var request = context.Request;
        var settings = options.Value;
        var stateChanging = !(HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method) || HttpMethods.IsOptions(request.Method) || HttpMethods.IsTrace(request.Method));
        var cookieAuthenticated = request.Cookies.ContainsKey(BffCookie.Name(request, settings));
        var bffEndpoint = request.Path.StartsWithSegments("/bff") && !request.Path.StartsWithSegments(BffPaths.BackchannelLogout);

        if (cookieAuthenticated && IsWebSocketHandshake(request) && !OriginAllowed(request, settings))
        {
            await TypedResults.Problem(
                detail: "WebSocket connections with the session cookie must come from an allowed origin.",
                statusCode: StatusCodes.Status403Forbidden,
                extensions: new Dictionary<string, object?> { ["code"] = "websocket_origin_not_allowed" }).ExecuteAsync(context).ConfigureAwait(false);
            return;
        }

        if (stateChanging && (cookieAuthenticated || bffEndpoint) && !request.Headers.ContainsKey(settings.CsrfHeaderName))
        {
            await TypedResults.Problem(
                detail: $"State-changing requests must send the {settings.CsrfHeaderName} header.",
                statusCode: StatusCodes.Status403Forbidden,
                extensions: new Dictionary<string, object?> { ["code"] = "csrf_header_missing" }).ExecuteAsync(context).ConfigureAwait(false);
            return;
        }

        await next(context).ConfigureAwait(false);
    }

    private static bool IsWebSocketHandshake(HttpRequest request) =>
        request.Headers.Upgrade.Any(value => value is not null && value.Contains("websocket", StringComparison.OrdinalIgnoreCase))
        || string.Equals(request.HttpContext.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpExtendedConnectFeature>()?.Protocol, "websocket", StringComparison.OrdinalIgnoreCase);

    /// <summary>The BFF's own origin, or a configured one. A handshake without an <c>Origin</c> header isn't from a browser page we serve.</summary>
    private static bool OriginAllowed(HttpRequest request, BffOptions settings)
    {
        var origin = request.Headers.Origin.ToString();
        if (string.IsNullOrEmpty(origin) || !Uri.TryCreate(origin, UriKind.Absolute, out var parsed))
        {
            return false;
        }

        return SameOrigin(parsed, $"{request.Scheme}://{request.Host}") || settings.WebSocketOrigins.Any(allowed => SameOrigin(parsed, allowed));
    }

    private static bool SameOrigin(Uri origin, string other) =>
        Uri.TryCreate(other, UriKind.Absolute, out var parsed)
        && string.Equals(origin.GetLeftPart(UriPartial.Authority), parsed.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Turns the session cookie into the session's bearer token for every request outside <c>/bff/*</c>. A request with the
/// cookie but no valid session has its Authorization header removed, so a bearer smuggled in next to a dead cookie is never
/// forwarded. A request without the cookie (an API client with its own token) is left alone. With delegation enabled, a live
/// derived session that belongs to the own session is used instead (impersonation or tenant switch); a dead one has its cookie
/// removed.
/// </summary>
public sealed class CookieToBearerMiddleware(RequestDelegate next, BffSessionManager sessions, IServiceProvider services, IOptions<BffOptions> options)
{
    /// <summary>Sets the bearer from the session (or acting session) cookie, then calls the next middleware.</summary>
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.Path.StartsWithSegments("/bff"))
        {
            var readOnly = HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method);
            var (token, problem) = await CurrentTokenAsync(context, sessions, services, options.Value, readOnly).ConfigureAwait(false);
            if (problem is not null)
            {
                await problem.ExecuteAsync(context).ConfigureAwait(false);
                return;
            }

            if (token is not null)
            {
                context.Request.Headers.Authorization = "Bearer " + token;
            }
            else if (context.Request.Cookies.ContainsKey(BffCookie.Name(context.Request, options.Value)))
            {
                context.Request.Headers.Authorization = default;
            }
        }

        await next(context).ConfigureAwait(false);
    }

    /// <summary>
    /// The access token a request of this browser acts with: its session's (refreshed when close to expiry), or its acting
    /// session's while impersonating or switched into a tenant. Null without a live session; a problem when the session store
    /// is down or the acting session ended (never a silent fall-back to the own session mid-action).
    /// </summary>
    internal static async Task<(string? Token, IResult? Problem)> CurrentTokenAsync(
        HttpContext context, BffSessionManager sessions, IServiceProvider services, BffOptions options, bool readOnly)
    {
        if (!context.Request.Cookies.TryGetValue(BffCookie.Name(context.Request, options), out var id) || string.IsNullOrEmpty(id))
        {
            return (null, null);
        }

        BffSession? session;
        try
        {
            session = await sessions.GetFreshAsync(id, readOnly, context.RequestAborted).ConfigureAwait(false);
        }
        catch (SessionStoreUnavailableException)
        {
            return (null, TypedResults.Problem(
                detail: "Sessions are temporarily unavailable. Try again shortly.",
                statusCode: StatusCodes.Status503ServiceUnavailable,
                extensions: new Dictionary<string, object?> { ["code"] = "session_store_unavailable" }));
        }

        if (session is null)
        {
            return (null, null);
        }

        var acting = BffCookie.ActingName(context.Request, options);
        if (!options.Delegation.Enabled || !context.Request.Cookies.TryGetValue(acting, out var derivedId) || string.IsNullOrEmpty(derivedId))
        {
            return (session.AccessToken, null);
        }

        BffSession? derived;
        try
        {
            derived = await services.GetRequiredService<DerivedSessionManager>().GetFreshAsync(derivedId, id, context.RequestAborted).ConfigureAwait(false);
        }
        catch (SessionStoreUnavailableException)
        {
            derived = null;
        }

        if (derived is not null)
        {
            return (derived.AccessToken, null);
        }

        context.Response.Cookies.Delete(acting, BffCookie.Options(context.Request, DateTimeOffset.UnixEpoch));
        return (null, TypedResults.Problem(
            detail: "The acting session has ended.",
            statusCode: StatusCodes.Status401Unauthorized,
            extensions: new Dictionary<string, object?> { ["code"] = "acting_session_ended" }));
    }
}

/// <summary>The BFF's own endpoints.</summary>
public static class BffPaths
{
    /// <summary>Starts sign-in with the authorization code flow and PKCE; an optional local <c>returnUrl</c> is where it ends.</summary>
    public const string Login = "/bff/login";
    /// <summary>The redirect URI the token server returns to; it creates the session and sets the session cookie.</summary>
    public const string Callback = "/bff/callback";
    /// <summary>Ends the session (a POST with the CSRF header) and answers the token server's end-session URL.</summary>
    public const string Logout = "/bff/logout";
    /// <summary>Answers the signed-in user's claims (<see cref="BffOptions.UserClaims"/>).</summary>
    public const string Me = "/bff/me";

    /// <summary>The current access token, for token-mediating mode (<see cref="BffOptions.TokenMediating"/>).</summary>
    public const string Token = "/bff/token";
    /// <summary>Receives OpenID Connect back-channel logout tokens from the token server; exempt from the CSRF header.</summary>
    public const string BackchannelLogout = "/bff/backchannel-logout";
    /// <summary>Answers what the browser is acting as: an impersonation, a tenant switch, or nothing.</summary>
    public const string Acting = "/bff/acting";
    /// <summary>Starts an impersonation session from an approved grant (POST).</summary>
    public const string StartImpersonation = "/bff/impersonation/{grantId}/start";
    /// <summary>Starts a session acting in another tenant (POST).</summary>
    public const string SwitchTenant = "/bff/tenants/{tenantId}/switch";
    /// <summary>Ends the derived session, and an impersonation grant at the token server (POST).</summary>
    public const string StopActing = "/bff/acting/stop";

    /// <summary>Forwards to the token server's own APIs with the own session's account token (<see cref="BffOptions.AccountApi"/>).</summary>
    public const string Account = "/bff/account/{**path}";
}

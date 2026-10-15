using JeffOps.Authentication.Bff.Sessions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Bff.Middleware;

/// <summary>The session cookie: <c>__Host-</c> prefixed on HTTPS, HttpOnly, SameSite=Lax.</summary>
public static class BffCookie
{
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
/// browser.
/// </summary>
public sealed class CsrfMiddleware(RequestDelegate next, IOptions<BffOptions> options)
{
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var request = context.Request;
        var settings = options.Value;
        var stateChanging = !(HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method) || HttpMethods.IsOptions(request.Method) || HttpMethods.IsTrace(request.Method));
        var cookieAuthenticated = request.Cookies.ContainsKey(BffCookie.Name(request, settings));
        var bffEndpoint = request.Path.StartsWithSegments("/bff") && !request.Path.StartsWithSegments(BffPaths.BackchannelLogout);

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
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!context.Request.Path.StartsWithSegments("/bff")
            && context.Request.Cookies.TryGetValue(BffCookie.Name(context.Request, options.Value), out var id)
            && !string.IsNullOrEmpty(id))
        {
            BffSession? session;
            try
            {
                var readOnly = HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method);
                session = await sessions.GetFreshAsync(id, readOnly, context.RequestAborted).ConfigureAwait(false);
            }
            catch (SessionStoreUnavailableException)
            {
                await TypedResults.Problem(
                    detail: "Sessions are temporarily unavailable. Try again shortly.",
                    statusCode: StatusCodes.Status503ServiceUnavailable,
                    extensions: new Dictionary<string, object?> { ["code"] = "session_store_unavailable" }).ExecuteAsync(context).ConfigureAwait(false);
                return;
            }

            if (session is null)
            {
                context.Request.Headers.Authorization = default;
            }
            else
            {
                var token = session.AccessToken;
                var acting = BffCookie.ActingName(context.Request, options.Value);
                if (options.Value.Delegation.Enabled
                    && context.Request.Cookies.TryGetValue(acting, out var derivedId)
                    && !string.IsNullOrEmpty(derivedId))
                {
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
                        token = derived.AccessToken;
                    }
                    else
                    {
                        // Never fall back to the own session silently mid-action: the request fails, the cookie goes.
                        context.Response.Cookies.Delete(acting, BffCookie.Options(context.Request, DateTimeOffset.UnixEpoch));
                        await TypedResults.Problem(
                            detail: "The acting session has ended.",
                            statusCode: StatusCodes.Status401Unauthorized,
                            extensions: new Dictionary<string, object?> { ["code"] = "acting_session_ended" }).ExecuteAsync(context).ConfigureAwait(false);
                        return;
                    }
                }

                context.Request.Headers.Authorization = "Bearer " + token;
            }
        }

        await next(context).ConfigureAwait(false);
    }
}

/// <summary>The BFF's own endpoints.</summary>
public static class BffPaths
{
    public const string Login = "/bff/login";
    public const string Callback = "/bff/callback";
    public const string Logout = "/bff/logout";
    public const string Me = "/bff/me";
    public const string BackchannelLogout = "/bff/backchannel-logout";
    public const string Acting = "/bff/acting";
    public const string StartImpersonation = "/bff/impersonation/{grantId}/start";
    public const string SwitchTenant = "/bff/tenants/{tenantId}/switch";
    public const string StopActing = "/bff/acting/stop";
}

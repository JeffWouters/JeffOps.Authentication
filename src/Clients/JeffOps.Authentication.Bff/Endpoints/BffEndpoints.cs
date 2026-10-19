using JeffOps.Authentication.Bff.Middleware;
using JeffOps.Authentication.Bff.Sessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;

namespace JeffOps.Authentication.Bff.Endpoints;

/// <summary>
/// Sign-in, sign-out, the current user, and back-channel logout. The browser only ever sees the session cookie.
/// </summary>
internal static partial class BffEndpoints
{
    private const string BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    public static void Map(IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup(string.Empty).ExcludeFromDescription().AllowAnonymous();

        group.MapGet(BffPaths.Login, Login);
        group.MapMethods(BffPaths.Callback, [HttpMethods.Get, HttpMethods.Post], CallbackAsync);
        group.MapPost(BffPaths.Logout, LogoutAsync);
        group.MapGet(BffPaths.Me, MeAsync);
        group.MapGet(BffPaths.Token, TokenAsync);
        group.MapPost(BffPaths.BackchannelLogout, BackchannelLogoutAsync).DisableAntiforgery();
    }

    /// <summary>Starts the authorization code flow (with PKCE) at the token server; comes back to <paramref name="returnUrl"/>.</summary>
    private static IResult Login(string? returnUrl, string? prompt, IOptions<BffOptions> options)
    {
        var properties = new AuthenticationProperties { RedirectUri = LocalOrRoot(returnUrl) };
        properties.Items[OpenIddictClientAspNetCoreConstants.Properties.Issuer] = options.Value.Authority!.AbsoluteUri;
        if (prompt is "login" or "none")
        {
            properties.Parameters[OpenIddict.Abstractions.OpenIddictConstants.Parameters.Prompt] = prompt;
        }

        return Results.Challenge(properties, [OpenIddictClientAspNetCoreDefaults.AuthenticationScheme]);
    }

    private static async Task<IResult> CallbackAsync(HttpContext context, BffSessionStore store, IOptions<BffOptions> options, TimeProvider time)
    {
        var result = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme).ConfigureAwait(false);
        var returnUrl = LocalOrRoot(result.Properties?.RedirectUri);

        if (!result.Succeeded || result.Properties is null)
        {
            // Refusals (for example mfa_required) come back as an error; the SPA reads it from the query string.
            var error = result.Properties?.GetString(OpenIddictClientAspNetCoreConstants.Properties.Error) ?? "access_denied";
            return Results.Redirect(Append(returnUrl, "error", error));
        }

        var accessToken = result.Properties.GetTokenValue(OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken);
        var subject = result.Principal?.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(subject))
        {
            return Results.Redirect(Append(returnUrl, "error", "invalid_response"));
        }

        var now = time.GetUtcNow();
        var accessExpiry = DateTimeOffset.TryParse(
            result.Properties.GetTokenValue(OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessTokenExpirationDate),
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal,
            out var parsed) ? parsed : now.AddMinutes(5);

        var session = new BffSession(
            subject,
            accessToken,
            result.Properties.GetTokenValue(OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken),
            result.Properties.GetTokenValue(OpenIddictClientAspNetCoreConstants.Tokens.BackchannelIdentityToken),
            accessExpiry,
            now + options.Value.SessionLifetime);

        var id = await store.CreateAsync(session, context.RequestAborted).ConfigureAwait(false);
        context.Response.Cookies.Append(BffCookie.Name(context.Request, options.Value), id, BffCookie.Options(context.Request, session.SessionEndsAt));

        // A new sign-in never inherits an acting session; it belonged to the previous own session.
        if (context.Request.Cookies.TryGetValue(BffCookie.ActingName(context.Request, options.Value), out var acting) && !string.IsNullOrEmpty(acting))
        {
            await store.DeleteAsync(acting, subject: null, context.RequestAborted).ConfigureAwait(false);
            context.Response.Cookies.Delete(BffCookie.ActingName(context.Request, options.Value), BffCookie.Options(context.Request, DateTimeOffset.UnixEpoch));
        }

        return Results.Redirect(returnUrl);
    }

    /// <summary>
    /// Ends the session (revoking its refresh token) and answers where the browser should go to end the session at the token
    /// server too: <c>{ "endSessionUrl": … }</c>. A POST with the CSRF header, so another site can't sign the user out. The
    /// URL names this client, not its ID token: tokens never reach JavaScript, and the token server ends the session its own
    /// sign-in cookie names.
    /// </summary>
    private static async Task<IResult> LogoutAsync(
        HttpContext context,
        BffSessionManager sessions,
        BffSessionStore store,
        IHttpClientFactory http,
        IOptions<BffOptions> options,
        ILoggerFactory loggers)
    {
        var cookie = BffCookie.Name(context.Request, options.Value);
        var actingCookie = BffCookie.ActingName(context.Request, options.Value);
        if (context.Request.Cookies.TryGetValue(cookie, out var id) && !string.IsNullOrEmpty(id))
        {
            var own = await store.GetAsync(id, context.RequestAborted).ConfigureAwait(false);

            // End an impersonation first, while the own session's token can still tell the token server.
            if (context.Request.Cookies.TryGetValue(actingCookie, out var actingId) && !string.IsNullOrEmpty(actingId))
            {
                var acting = await store.GetAsync(actingId, context.RequestAborted).ConfigureAwait(false);
                await store.DeleteAsync(actingId, acting?.Subject, context.RequestAborted).ConfigureAwait(false);
                if (acting is { Kind: DerivedSessionManager.Impersonation, GrantId: { } grantId } && own is not null && DerivedSessionManager.BelongsTo(acting, id)
                    && await sessions.GetAccountTokenAsync(id, context.RequestAborted).ConfigureAwait(false) is { } accountToken)
                {
                    await ActingEndpoints.EndGrantAsync(http, options.Value, grantId, accountToken, loggers.CreateLogger("JeffOps.Authentication.Bff.Acting"), context.RequestAborted).ConfigureAwait(false);
                }
            }

            await sessions.EndAsync(id, context.RequestAborted).ConfigureAwait(false);
        }

        context.Response.Cookies.Delete(cookie, BffCookie.Options(context.Request, DateTimeOffset.UnixEpoch));
        context.Response.Cookies.Delete(actingCookie, BffCookie.Options(context.Request, DateTimeOffset.UnixEpoch));

        var endSession = new Uri(options.Value.Authority!, "connect/endsession").AbsoluteUri + "?client_id=" + Uri.EscapeDataString(options.Value.ClientId!);
        return TypedResults.Ok(new { endSessionUrl = endSession });
    }

    /// <summary>The signed-in user's claims (from the access token), or 401.</summary>
    private static async Task<IResult> MeAsync(HttpContext context, BffSessionManager sessions, IOptions<BffOptions> options)
    {
        if (!context.Request.Cookies.TryGetValue(BffCookie.Name(context.Request, options.Value), out var id) || string.IsNullOrEmpty(id))
        {
            return TypedResults.Unauthorized();
        }

        var session = await sessions.GetFreshAsync(id, readOnlyRequest: true, context.RequestAborted).ConfigureAwait(false);
        if (session is null)
        {
            return TypedResults.Unauthorized();
        }

        // The token came from the token server over TLS and is not trusted for anything here; it's only displayed.
        var token = new JsonWebToken(session.AccessToken);
        var wanted = options.Value.UserClaims.ToHashSet(StringComparer.Ordinal);
        var claims = token.Claims
            .Where(claim => wanted.Contains(claim.Type))
            .GroupBy(claim => claim.Type)
            .ToDictionary(group => group.Key, group => group.Count() == 1 ? (object)group.First().Value : group.Select(claim => claim.Value).ToArray());

        return TypedResults.Ok(claims);
    }

    /// <summary>
    /// Token-mediating mode: the access token this browser's requests act with, for the app to call an API directly. Only
    /// with <see cref="BffOptions.TokenMediating"/>; the CSRF header is required so another site can't make the request.
    /// </summary>
    private static async Task<IResult> TokenAsync(HttpContext context, BffSessionManager sessions, IOptions<BffOptions> options)
    {
        var settings = options.Value;
        if (!settings.TokenMediating)
        {
            return TypedResults.NotFound();
        }

        if (!context.Request.Headers.ContainsKey(settings.CsrfHeaderName))
        {
            return TypedResults.Problem(
                detail: $"Requests for the token must send the {settings.CsrfHeaderName} header.",
                statusCode: StatusCodes.Status403Forbidden,
                extensions: new Dictionary<string, object?> { ["code"] = "csrf_header_required" });
        }

        var (token, problem) = await CookieToBearerMiddleware.CurrentTokenAsync(context, sessions, context.RequestServices, settings, readOnly: true).ConfigureAwait(false);
        if (problem is not null)
        {
            return problem;
        }

        if (token is null)
        {
            return TypedResults.Unauthorized();
        }

        context.Response.Headers.CacheControl = "no-store";
        var expires = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(token).ValidTo;
        return TypedResults.Ok(new { access_token = token, token_type = "Bearer", expires_at = new DateTimeOffset(expires, TimeSpan.Zero).ToUnixTimeSeconds() });
    }

    /// <summary>
    /// OpenID Connect Back-Channel Logout: the token server posts a signed <c>logout_token</c>; the session it names (<c>sid</c>)
    /// ends, or every session of that user when it names none. The token is validated against the token server's signing keys, audience, event and freshness, and each
    /// <c>jti</c> is accepted once.
    /// </summary>
    private static async Task<IResult> BackchannelLogoutAsync(
        HttpContext context,
        OpenIddictClientService client,
        BffSessionStore store,
        IMemoryCache replay,
        IOptions<BffOptions> options,
        TimeProvider time,
        ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger("JeffOps.Authentication.Bff.BackchannelLogout");
        if (!context.Request.HasFormContentType)
        {
            return TypedResults.BadRequest();
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
        var logoutToken = form["logout_token"].ToString();
        if (string.IsNullOrEmpty(logoutToken))
        {
            return TypedResults.BadRequest();
        }

        var registration = await client.GetClientRegistrationByIssuerAsync(options.Value.Authority!, context.RequestAborted).ConfigureAwait(false);
        var configuration = await registration.ConfigurationManager!.GetConfigurationAsync(context.RequestAborted).ConfigureAwait(false);

        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(logoutToken, new TokenValidationParameters
        {
            ValidIssuer = configuration.Issuer!.AbsoluteUri,
            ValidAudience = options.Value.ClientId,
            IssuerSigningKeys = configuration.SigningKeys,
            ValidateLifetime = false, // logout tokens may carry no exp; freshness is checked on iat below
            ClockSkew = TimeSpan.FromMinutes(2),
        }).ConfigureAwait(false);

        if (!validation.IsValid
            || validation.SecurityToken is not JsonWebToken token
            || !token.TryGetPayloadValue<Dictionary<string, object>>("events", out var events)
            || !events.ContainsKey(BackchannelLogoutEvent)
            || token.TryGetPayloadValue<string>("nonce", out _)
            || time.GetUtcNow() - token.IssuedAt > TimeSpan.FromMinutes(5)
            || string.IsNullOrEmpty(token.Id)
            || string.IsNullOrEmpty(token.Subject))
        {
            LogRejected(logger, validation.Exception?.Message);
            return TypedResults.BadRequest();
        }

        if (!replay.TryGetValue("jeffops:bff:logout-jti:" + token.Id, out _))
        {
            replay.Set("jeffops:bff:logout-jti:" + token.Id, true, TimeSpan.FromMinutes(10));
            // A token naming one session (sid) ends that session; without one, every session of the user.
            var ended = token.TryGetPayloadValue<string>("sid", out var sessionId) && !string.IsNullOrEmpty(sessionId)
                ? await store.DeleteSessionAsync(token.Subject, sessionId, context.RequestAborted).ConfigureAwait(false)
                : await store.DeleteAllAsync(token.Subject, context.RequestAborted).ConfigureAwait(false);
            LogEnded(logger, ended);
        }

        context.Response.Headers.CacheControl = "no-store";
        return TypedResults.Ok();
    }

    internal static string LocalOrRoot(string? returnUrl) =>
        Abstractions.Http.LocalRedirect.OrRoot(returnUrl);

    private static string Append(string url, string name, string value) =>
        url + (url.Contains('?', StringComparison.Ordinal) ? '&' : '?') + name + "=" + Uri.EscapeDataString(value);

    [LoggerMessage(EventId = 9111, Level = LogLevel.Warning, Message = "Rejected a back-channel logout token: {Reason}")]
    private static partial void LogRejected(ILogger logger, string? reason);

    [LoggerMessage(EventId = 9112, Level = LogLevel.Information, Message = "Back-channel logout ended {Count} sessions.")]
    private static partial void LogEnded(ILogger logger, int count);

    private static string? GetString(this AuthenticationProperties properties, string key) =>
        properties.Items.TryGetValue(key, out var value) ? value : null;
}

using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Abstractions.Http;
using JeffOps.Authentication.Abstractions.Replay;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Features.Sessions.EndSession;
using JeffOps.Authentication.Application.Features.Federation.CompleteExternalSignIn;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.SharedKernel.Handlers;
using AuthenticationBuilder = JeffOps.Authentication.Application.DependencyInjection.AuthenticationBuilder;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace JeffOps.Authentication.Federation.Oidc;

/// <summary>
/// OpenID Connect providers tenants register themselves (docs/DESIGN.md §8.4). They can't be OpenIddict client
/// registrations, which are fixed at startup, so this is a small relying party of its own: the authorization code flow with
/// PKCE, <c>state</c> and <c>nonce</c> bound to the browser, and the ID token checked against the provider's published keys.
/// Everything is fetched from the tenant's issuer through a client that reaches public addresses only. Single logout both
/// ways: signing out here sends the browser to the provider's <c>end_session_endpoint</c> (RP-Initiated Logout 1.0), and the
/// provider's <c>logout_token</c> at <c>signin/oidc/{provider}/backchannel-logout</c> ends the sessions it names
/// (Back-Channel Logout 1.0).
/// </summary>
public static partial class TenantOidcEndpoints
{
    /// <summary>The route prefix: <c>signin/oidc/{provider}</c> starts a sign-in, <c>signin/oidc/{provider}/callback</c> ends it.</summary>
    public const string Prefix = "signin/oidc";

    /// <summary>The HTTP client used for tenants' issuers: public addresses only, no redirects.</summary>
    public const string HttpClientName = "JeffOps.Oidc.TenantProviders";

    private const string LoginPath = "/account/login";
    private const int MaxResponseBytes = 512 * 1024;
    private static readonly TimeSpan SignInTimeout = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan LogoutTokenMaxAge = TimeSpan.FromMinutes(5);
    private const string BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    /// <summary>The session claim naming the tenant OIDC provider a sign-in came from.</summary>
    internal const string ProviderClaim = "jeffops:oidc:provider";

    /// <summary>The session claim holding the provider's ID token, the <c>id_token_hint</c> for logging out there.</summary>
    internal const string IdTokenClaim = "jeffops:oidc:id_token";

    private static readonly string[] Algorithms =
    [
        SecurityAlgorithms.RsaSha256, SecurityAlgorithms.RsaSha384, SecurityAlgorithms.RsaSha512,
        SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.RsaSsaPssSha384, SecurityAlgorithms.RsaSsaPssSha512,
        SecurityAlgorithms.EcdsaSha256, SecurityAlgorithms.EcdsaSha384, SecurityAlgorithms.EcdsaSha512,
    ];

    /// <summary>
    /// Lets tenants sign their people in through OpenID Connect providers they register (with the Enterprise module, once a
    /// platform operator allows the tenant). Map the endpoints with <see cref="MapJeffOpsTenantOidc"/>.
    /// </summary>
    public static AuthenticationBuilder AddOidcTenantProviders(this AuthenticationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        var services = builder.Services;
        services.AddDataProtection();
        services.AddHttpClient(HttpClientName)
            .ConfigureHttpClient(client => client.Timeout = TimeSpan.FromSeconds(15))
            .ConfigurePrimaryHttpMessageHandler(PublicNetwork.Handler);
        services.TryAddSingleton<TenantOidcDocuments>();
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IExternalProviderChallenge, TenantOidcChallenge>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IExternalSignOut, TenantOidcSignOut>());
        return builder;
    }

    /// <summary>
    /// Maps <c>signin/oidc/{provider}</c> (start), <c>/callback</c> (the redirect URI), <c>/signed-out</c> (the post-logout
    /// redirect URI) and <c>/backchannel-logout</c> (the back-channel logout URI); anonymous, left out of the API description.
    /// </summary>
    public static IEndpointRouteBuilder MapJeffOpsTenantOidc(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var group = endpoints.MapGroup(Prefix).AllowAnonymous().ExcludeFromDescription();
        group.MapGet("{provider}", StartAsync);
        group.MapGet("{provider}/callback", CallbackAsync);
        group.MapGet("{provider}/signed-out", SignedOut);
        group.MapPost("{provider}/backchannel-logout", BackchannelLogoutAsync).DisableAntiforgery();
        return endpoints;
    }

    private static async Task<IResult> StartAsync(
        string provider,
        string? returnUrl,
        string? login_hint,
        HttpContext context,
        ITenantProviderDirectory directory,
        TenantOidcDocuments documents,
        IDataProtectionProvider dataProtection,
        TimeProvider time,
        ILoggerFactory loggers)
    {
        if (!TenantProviderNames.IsOidc(provider) || await directory.FindOidcAsync(provider, context.RequestAborted).ConfigureAwait(false) is not { } settings)
        {
            return TypedResults.NotFound();
        }

        var local = LocalRedirect.OrRoot(returnUrl);
        TenantOidcDocument document;
        try
        {
            document = await documents.GetAsync(settings.Issuer, context.RequestAborted).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // A provider that can't be reached or describes itself wrongly refuses the sign-in.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogUnavailable(loggers.CreateLogger(LoggerName), exception, provider);
            return BackToLogin(local, "provider_unavailable");
        }

        var state = new PendingSignIn(Random(), Random(), Random(), local, (time.GetUtcNow() + SignInTimeout).ToUnixTimeSeconds());
        context.Response.Cookies.Append(CookieName(provider), Protector(dataProtection, provider).Protect(JsonSerializer.Serialize(state)), new CookieOptions
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            // The provider sends the browser back with a top-level GET: Lax is enough.
            SameSite = SameSiteMode.Lax,
            Path = $"/{Prefix}/{provider}",
            Expires = DateTimeOffset.FromUnixTimeSeconds(state.ExpiresAt),
            IsEssential = true,
        });

        var scopes = settings.Scopes.Count == 0 ? ["profile", "email"] : settings.Scopes;
        var query = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = settings.ClientId,
            ["redirect_uri"] = RedirectUri(context, provider),
            ["scope"] = string.Join(' ', new[] { "openid" }.Concat(scopes)),
            ["state"] = state.State,
            ["nonce"] = state.Nonce,
            ["code_challenge"] = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(state.Verifier))),
            ["code_challenge_method"] = "S256",
        };
        if (!string.IsNullOrWhiteSpace(login_hint))
        {
            query["login_hint"] = login_hint;
        }

        // The client asked for a fresh sign-in: so does this server, of the provider.
        if (FreshSignIn.RequiredAfter(local, time.GetUtcNow()) is { } after)
        {
            query["prompt"] = "login";
            query["max_age"] = FreshSignIn.MaxAge(after, time.GetUtcNow()).ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        var endpoint = document.Configuration.AuthorizationEndpoint;
        var separator = endpoint.Contains('?', StringComparison.Ordinal) ? '&' : '?';
        return Results.Redirect(endpoint + separator + string.Join('&', query.Select(pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}")));
    }

    private static async Task<IResult> CallbackAsync(
        string provider,
        HttpContext context,
        ITenantProviderDirectory directory,
        TenantOidcDocuments documents,
        IDataProtectionProvider dataProtection,
        IHttpClientFactory httpClients,
        IReplayCache replay,
        IHomeRealmDirectory realms,
        ICommandHandler<CompleteExternalSignInCommand, ExternalSignInResult> completeSignIn,
        IOptions<TokenServerOptions> tokenServer,
        IOptions<FederationOptions> federation,
        IExternalSessions externalSessions,
        ClaimNames names,
        TimeProvider time,
        ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(LoggerName);
        if (!TenantProviderNames.IsOidc(provider) || await directory.FindOidcAsync(provider, context.RequestAborted).ConfigureAwait(false) is not { } settings)
        {
            return TypedResults.NotFound();
        }

        var pending = ReadState(context, provider, dataProtection, time);
        context.Response.Cookies.Delete(CookieName(provider), new CookieOptions { Path = $"/{Prefix}/{provider}", Secure = context.Request.IsHttps, SameSite = SameSiteMode.Lax });
        if (pending is null)
        {
            LogRejected(logger, provider, "no pending sign-in for this browser");
            return BackToLogin("/", "signin_expired");
        }

        var query = context.Request.Query;
        if (!FixedTimeEquals(query["state"].ToString(), pending.State))
        {
            LogRejected(logger, provider, "state does not match this browser's sign-in");
            return BackToLogin(pending.ReturnUrl, "provider_error");
        }

        if (!string.IsNullOrEmpty(query["error"]) || query["code"].ToString() is not { Length: > 0 } code)
        {
            LogProviderError(logger, provider, ErrorCodeOf(query["error"].ToString()));
            return BackToLogin(pending.ReturnUrl, "provider_error");
        }

        JsonWebToken idToken;
        string rawIdToken;
        string? email;
        try
        {
            var document = await documents.GetAsync(settings.Issuer, context.RequestAborted).ConfigureAwait(false);
            using var client = httpClients.CreateClient(HttpClientName);
            var tokens = await RedeemAsync(client, document, settings, code, RedirectUri(context, provider), pending.Verifier, context.RequestAborted).ConfigureAwait(false);
            rawIdToken = tokens.IdToken;
            idToken = await ValidateAsync(documents, document, settings, tokens.IdToken, time, context.RequestAborted).ConfigureAwait(false);
            if (!idToken.TryGetPayloadValue<string>("nonce", out var nonce) || !FixedTimeEquals(nonce, pending.Nonce))
            {
                throw new SecurityTokenValidationException("The ID token's nonce doesn't match this browser's sign-in.");
            }

            if (!await replay.TryAddAsync(ReplayKeys.For("oidc-nonce", provider + "|" + nonce), new DateTimeOffset(idToken.ValidTo, TimeSpan.Zero) + ClockSkew, context.RequestAborted).ConfigureAwait(false))
            {
                throw new SecurityTokenReplayDetectedException("The ID token was used before.");
            }

            email = Claim(idToken, "email")
                ?? await UserInfoEmailAsync(client, document, tokens.AccessToken, idToken.Subject, context.RequestAborted).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // Any failure to redeem the code or validate the tokens refuses the sign-in (fail closed).
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogInvalid(logger, exception, provider);
            return BackToLogin(pending.ReturnUrl, "provider_error");
        }

        if (string.IsNullOrEmpty(idToken.Subject))
        {
            LogRejected(logger, provider, "the ID token names no subject");
            return BackToLogin(pending.ReturnUrl, "provider_error");
        }

        // A fresh sign-in was asked for: the provider's own single sign-on session, from before, doesn't count.
        if (!FreshSignIn.ProviderAuthenticatedInTime(FreshSignIn.AuthTime(Claim(idToken, "auth_time")), FreshSignIn.RequiredAfter(pending.ReturnUrl, time.GetUtcNow())))
        {
            LogRejected(logger, provider, "authenticated before the fresh sign-in the client asked for");
            return BackToLogin(pending.ReturnUrl, FreshSignIn.ReauthenticationRequired);
        }

        // A tenant's own provider signs in only that tenant's people: addresses in the domains the tenant verified. The tenant
        // vouches for those, so the address counts as verified.
        if (HomeRealm.DomainOf(email) is not { } domain
            || await realms.FindByDomainAsync(domain, context.RequestAborted).ConfigureAwait(false) is not { } realm
            || realm.TenantId != settings.TenantId)
        {
            LogRejected(logger, provider, "address outside the tenant's verified domains");
            return BackToLogin(pending.ReturnUrl, "domain_not_allowed");
        }

        var identity = new ExternalIdentity(
            provider,
            new ExternalLoginKey("urn:jeffops:tenant-provider:" + provider[TenantProviderNames.OidcPrefix.Length..], idToken.Subject),
            email,
            EmailVerified: true,
            Claim(idToken, "name"),
            Strength(idToken, settings, federation.Value));
        var signedIn = await completeSignIn.HandleAsync(new CompleteExternalSignInCommand(identity), context.RequestAborted).ConfigureAwait(false);
        if (signedIn.IsFailure)
        {
            return BackToLogin(pending.ReturnUrl, signedIn.Error.Code);
        }

        // Remember where the session came from: signing out here signs out at the provider too, and the provider's logout
        // (by its session, or by the user) can find this session.
        var scheme = tokenServer.Value.SignInScheme;
        var now = time.GetUtcNow();
        var principal = SignInPrincipal.Create(signedIn.Value.AccountId, signedIn.Value.Strength, now, names, scheme, provider);
        var session = (System.Security.Claims.ClaimsIdentity)principal.Identity!;
        session.AddClaim(new System.Security.Claims.Claim(ProviderClaim, provider));
        session.AddClaim(new System.Security.Claims.Claim(IdTokenClaim, rawIdToken));
        await externalSessions.RecordAsync(
            provider, Claim(idToken, "sid"), signedIn.Value.AccountId, SignInPrincipal.SessionId(principal, names)!, now + tokenServer.Value.LongestSessionLifetime, context.RequestAborted).ConfigureAwait(false);

        await context.SignInAsync(scheme, principal).ConfigureAwait(false);
        return Results.Redirect(pending.ReturnUrl);
    }

    /// <summary>The provider sends the browser back after logging out there: continue where signing out here left off.</summary>
    private static IResult SignedOut(string provider, string? state, IDataProtectionProvider dataProtection, TimeProvider time) =>
        Results.Redirect(TenantOidcSignOut.ReadState(state, provider, dataProtection, time) ?? "/");

    /// <summary>
    /// Back-Channel Logout 1.0: the provider posts a signed <c>logout_token</c> naming its session (<c>sid</c>), the user
    /// (<c>sub</c>), or both. Every session here that sign-ins through this provider started for them ends: tokens stop
    /// refreshing, the browser's sign-in stops working, and clients are told in turn.
    /// </summary>
    private static async Task<IResult> BackchannelLogoutAsync(
        string provider,
        HttpContext context,
        ITenantProviderDirectory directory,
        TenantOidcDocuments documents,
        IReplayCache replay,
        IExternalSessions externalSessions,
        IAccountRepository accounts,
        ICommandHandler<EndSessionCommand> endSession,
        TimeProvider time,
        ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger(LoggerName);
        context.Response.Headers.CacheControl = "no-store";
        if (!TenantProviderNames.IsOidc(provider) || await directory.FindOidcAsync(provider, context.RequestAborted).ConfigureAwait(false) is not { } settings)
        {
            return TypedResults.NotFound();
        }

        if (!context.Request.HasFormContentType
            || (await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false))["logout_token"].ToString() is not { Length: > 0 } logoutToken)
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "A logout_token is required." });
        }

        JsonWebToken token;
        try
        {
            token = await ValidateLogoutTokenAsync(documents, settings, logoutToken, time, context.RequestAborted).ConfigureAwait(false);
            if (!await replay.TryAddAsync(ReplayKeys.For("oidc-logout", provider + "|" + token.Id), time.GetUtcNow() + LogoutTokenMaxAge + ClockSkew, context.RequestAborted).ConfigureAwait(false))
            {
                throw new SecurityTokenReplayDetectedException("The logout token was used before.");
            }
        }
#pragma warning disable CA1031 // Any invalid logout token is refused, never acted on.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogInvalid(logger, exception, provider);
            return Results.BadRequest(new { error = "invalid_request", error_description = "The logout token is not valid." });
        }

        Guid? accountId = null;
        var subject = Claim(token, "sub");
        if (subject is not null)
        {
            var login = new ExternalLoginKey("urn:jeffops:tenant-provider:" + provider[TenantProviderNames.OidcPrefix.Length..], subject);
            if (await accounts.FindByExternalLoginAsync(login, context.RequestAborted).ConfigureAwait(false) is not { } account)
            {
                return Results.Ok();
            }

            accountId = account.Id;
        }

        var ended = await externalSessions.FindAsync(provider, Claim(token, "sid"), accountId, context.RequestAborted).ConfigureAwait(false);
        foreach (var session in ended)
        {
            await endSession.HandleAsync(new EndSessionCommand(session.AccountId, session.SessionId), context.RequestAborted).ConfigureAwait(false);
        }

        await externalSessions.RemoveAsync([.. ended.Select(session => session.SessionId)], context.RequestAborted).ConfigureAwait(false);
        LogBackchannelLogout(logger, provider, ended.Count);
        return Results.Ok();
    }

    /// <summary>
    /// A logout token (Back-Channel Logout 1.0 §2.6): signed by the provider's keys, its issuer, this client as audience,
    /// issued in the last five minutes, the logout event, a <c>jti</c>, <c>sub</c> or <c>sid</c>, and no <c>nonce</c> (so
    /// an ID token can't pass for one).
    /// </summary>
    private static async Task<JsonWebToken> ValidateLogoutTokenAsync(
        TenantOidcDocuments documents, TenantOidcProvider settings, string logoutToken, TimeProvider time, CancellationToken cancellationToken)
    {
        var document = await documents.GetAsync(settings.Issuer, cancellationToken).ConfigureAwait(false);
        var handler = new JsonWebTokenHandler { MapInboundClaims = false };
        var result = await handler.ValidateTokenAsync(logoutToken, LogoutParameters(document, settings, time)).ConfigureAwait(false);
        if (result.Exception is SecurityTokenSignatureKeyNotFoundException)
        {
            document = await documents.RefreshKeysAsync(settings.Issuer, cancellationToken).ConfigureAwait(false);
            result = await handler.ValidateTokenAsync(logoutToken, LogoutParameters(document, settings, time)).ConfigureAwait(false);
        }

        if (!result.IsValid)
        {
            throw result.Exception ?? new SecurityTokenValidationException("The logout token is not valid.");
        }

        var token = (JsonWebToken)result.SecurityToken;
        var now = time.GetUtcNow();
        if (token.Typ is { Length: > 0 } typ && !typ.Equals("logout+jwt", StringComparison.OrdinalIgnoreCase) && !typ.Equals("JWT", StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityTokenValidationException($"A logout token isn't typed '{typ}'.");
        }

        if (!token.TryGetPayloadValue<long>("iat", out var issuedAt)
            || DateTimeOffset.FromUnixTimeSeconds(issuedAt) < now - LogoutTokenMaxAge - ClockSkew
            || DateTimeOffset.FromUnixTimeSeconds(issuedAt) > now + ClockSkew)
        {
            throw new SecurityTokenValidationException("The logout token wasn't issued just now.");
        }

        if (!token.TryGetPayloadValue<JsonElement>("events", out var events) || events.ValueKind != JsonValueKind.Object
            || !events.TryGetProperty(BackchannelLogoutEvent, out var logout) || logout.ValueKind != JsonValueKind.Object)
        {
            throw new SecurityTokenValidationException("The token isn't a logout token.");
        }

        if (token.TryGetPayloadValue<object>("nonce", out _))
        {
            throw new SecurityTokenValidationException("A logout token has no nonce.");
        }

        if (string.IsNullOrEmpty(token.Id) || (Claim(token, "sub") is null && Claim(token, "sid") is null))
        {
            throw new SecurityTokenValidationException("A logout token needs a jti, and a sub or sid.");
        }

        if (token.TryGetPayloadValue<string>("azp", out var azp) ? azp != settings.ClientId : token.Audiences.Count() > 1)
        {
            throw new SecurityTokenInvalidAudienceException("The logout token was issued to another client.");
        }

        return token;
    }

    private static TokenValidationParameters LogoutParameters(TenantOidcDocument document, TenantOidcProvider settings, TimeProvider time)
    {
        var parameters = Parameters(document, settings, time);
        parameters.RequireExpirationTime = false;
        parameters.LifetimeValidator = (notBefore, expires, _, _) =>
        {
            var now = time.GetUtcNow().UtcDateTime;
            return (expires is not { } until || until > now - ClockSkew) && (notBefore is not { } from || from <= now + ClockSkew);
        };
        return parameters;
    }

    /// <summary>Redeems the code at the token endpoint, authenticating as the provider allows (RFC 6749 §2.3.1).</summary>
    private static async Task<(string IdToken, string? AccessToken)> RedeemAsync(
        HttpClient client, TenantOidcDocument document, TenantOidcProvider settings, string code, string redirectUri, string verifier, CancellationToken cancellationToken)
    {
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["code_verifier"] = verifier,
        };
        using var request = new HttpRequestMessage(HttpMethod.Post, document.Configuration.TokenEndpoint);
        var methods = document.Configuration.TokenEndpointAuthMethodsSupported;
        if (settings.ClientSecret is not { } secret)
        {
            form["client_id"] = settings.ClientId;
        }
        else if (methods.Count == 0 || methods.Contains("client_secret_basic"))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(
                $"{Uri.EscapeDataString(settings.ClientId)}:{Uri.EscapeDataString(secret)}")));
        }
        else if (methods.Contains("client_secret_post"))
        {
            form["client_id"] = settings.ClientId;
            form["client_secret"] = secret;
        }
        else
        {
            throw new InvalidOperationException("The provider supports neither client_secret_basic nor client_secret_post.");
        }

        request.Content = new FormUrlEncodedContent(form);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        var body = await PublicNetwork.ReadLimitedAsync(response, MaxResponseBytes, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"The token endpoint answered {(int)response.StatusCode}.");
        }

        using var json = JsonDocument.Parse(body);
        var root = json.RootElement;
        if (!root.TryGetProperty("id_token", out var idToken) || idToken.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException("The token response has no ID token.");
        }

        return (idToken.GetString()!, root.TryGetProperty("access_token", out var access) && access.ValueKind == JsonValueKind.String ? access.GetString() : null);
    }

    /// <summary>Checks the ID token's signature (the provider's published keys, asymmetric algorithms only), issuer, audience and lifetime.</summary>
    private static async Task<JsonWebToken> ValidateAsync(
        TenantOidcDocuments documents, TenantOidcDocument document, TenantOidcProvider settings, string idToken, TimeProvider time, CancellationToken cancellationToken)
    {
        var handler = new JsonWebTokenHandler { MapInboundClaims = false };
        var result = await handler.ValidateTokenAsync(idToken, Parameters(document, settings, time)).ConfigureAwait(false);
        if (result.Exception is SecurityTokenSignatureKeyNotFoundException)
        {
            // The provider may have rolled its keys since they were read.
            document = await documents.RefreshKeysAsync(settings.Issuer, cancellationToken).ConfigureAwait(false);
            result = await handler.ValidateTokenAsync(idToken, Parameters(document, settings, time)).ConfigureAwait(false);
        }

        if (!result.IsValid)
        {
            throw result.Exception ?? new SecurityTokenValidationException("The ID token is not valid.");
        }

        var token = (JsonWebToken)result.SecurityToken;
        if (token.TryGetPayloadValue<string>("azp", out var azp) ? azp != settings.ClientId : token.Audiences.Count() > 1)
        {
            throw new SecurityTokenInvalidAudienceException("The ID token was issued to another client.");
        }

        return token;
    }

    private static TokenValidationParameters Parameters(TenantOidcDocument document, TenantOidcProvider settings, TimeProvider time) => new()
    {
        ValidIssuer = document.Configuration.Issuer,
        ValidAudience = settings.ClientId,
        IssuerSigningKeys = document.Keys,
        ValidAlgorithms = Algorithms,
        RequireSignedTokens = true,
        RequireExpirationTime = true,
        ValidateLifetime = true,
        LifetimeValidator = (notBefore, expires, _, _) =>
        {
            var now = time.GetUtcNow().UtcDateTime;
            return expires is { } until && until > now - ClockSkew && (notBefore is not { } from || from <= now + ClockSkew);
        },
    };

    /// <summary>The email from the UserInfo endpoint, when the ID token has none; it must describe the same subject (OIDC Core §5.3.2).</summary>
    private static async Task<string?> UserInfoEmailAsync(HttpClient client, TenantOidcDocument document, string? accessToken, string subject, CancellationToken cancellationToken)
    {
        if (accessToken is null || string.IsNullOrEmpty(document.Configuration.UserInfoEndpoint))
        {
            return null;
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, document.Configuration.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        var body = await PublicNetwork.ReadLimitedAsync(response, MaxResponseBytes, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode || response.Content.Headers.ContentType?.MediaType != "application/json")
        {
            return null;
        }

        using var json = JsonDocument.Parse(body);
        var root = json.RootElement;
        return root.TryGetProperty("sub", out var sub) && sub.ValueKind == JsonValueKind.String && sub.GetString() == subject
            && root.TryGetProperty("email", out var email) && email.ValueKind == JsonValueKind.String
            ? email.GetString()
            : null;
    }

    private static AuthenticationStrength Strength(JsonWebToken token, TenantOidcProvider settings, FederationOptions options)
    {
        var methods = token.TryGetPayloadValue<string[]>("amr", out var amr) ? amr : [];
        var strength = new AuthenticationStrength(methods);
        return Claim(token, "acr") is { } acr
            && (settings.MultiFactorAcrValues.Contains(acr, StringComparer.Ordinal) || options.MultiFactorAuthenticationContexts.Contains(acr, StringComparer.OrdinalIgnoreCase))
            ? strength.WithMultiFactor()
            : strength;
    }

    private static string? Claim(JsonWebToken token, string name) =>
        token.TryGetPayloadValue<string>(name, out var value) && !string.IsNullOrWhiteSpace(value) ? value : null;

    private static PendingSignIn? ReadState(HttpContext context, string provider, IDataProtectionProvider dataProtection, TimeProvider time)
    {
        if (!context.Request.Cookies.TryGetValue(CookieName(provider), out var value) || string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            var state = JsonSerializer.Deserialize<PendingSignIn>(Protector(dataProtection, provider).Unprotect(value));
            return state is not null && DateTimeOffset.FromUnixTimeSeconds(state.ExpiresAt) > time.GetUtcNow()
                ? state with { ReturnUrl = LocalRedirect.OrRoot(state.ReturnUrl) }
                : null;
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException)
        {
            return null;
        }
    }

    private static IDataProtector Protector(IDataProtectionProvider dataProtection, string provider) =>
        dataProtection.CreateProtector("JeffOps.Oidc.TenantSignIn.v1", provider);

    private static string RedirectUri(HttpContext context, string provider) =>
        $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/{Prefix}/{provider}/callback";

    private static string CookieName(string provider) => "jeffops-oidc-" + provider;

    private static string Random() => Base64Url(RandomNumberGenerator.GetBytes(32));

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool FixedTimeEquals(string? left, string right) =>
        left is not null && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(left), Encoding.UTF8.GetBytes(right));

    private static IResult BackToLogin(string returnUrl, string error) =>
        Results.Redirect($"{LoginPath}?returnUrl={Uri.EscapeDataString(returnUrl)}&error={Uri.EscapeDataString(error)}");

    private const string LoggerName = "JeffOps.Authentication.Federation.Oidc.Tenants";

    /// <summary>The error codes of OAuth 2.0 and OpenID Connect authorization responses, the only ones logged as given.</summary>
    private static readonly FrozenSet<string> KnownErrors = FrozenSet.Create(StringComparer.Ordinal,
        "invalid_request", "unauthorized_client", "access_denied", "unsupported_response_type", "invalid_scope", "server_error",
        "temporarily_unavailable", "interaction_required", "login_required", "account_selection_required", "consent_required",
        "invalid_request_uri", "invalid_request_object", "request_not_supported", "request_uri_not_supported", "registration_not_supported");

    /// <summary>
    /// The provider's <c>error</c> as it may reach the log: a known code, <c>none</c> when there is none (no code either), or
    /// <c>other</c>. The value comes from the browser, so it is never logged as given.
    /// </summary>
    internal static string ErrorCodeOf(string? error) =>
        string.IsNullOrEmpty(error) ? "none" : KnownErrors.Contains(error) ? error : "other";

    [LoggerMessage(EventId = 8601, Level = LogLevel.Warning, Message = "Rejected a sign-in through tenant OIDC provider {Provider}: {Reason}")]
    private static partial void LogRejected(ILogger logger, string provider, string reason);

    [LoggerMessage(EventId = 8602, Level = LogLevel.Warning, Message = "An invalid answer from tenant OIDC provider {Provider} was rejected.")]
    private static partial void LogInvalid(ILogger logger, Exception exception, string provider);

    [LoggerMessage(EventId = 8603, Level = LogLevel.Warning, Message = "Tenant OIDC provider {Provider} could not be reached or described itself wrongly.")]
    private static partial void LogUnavailable(ILogger logger, Exception exception, string provider);

    [LoggerMessage(EventId = 8605, Level = LogLevel.Warning, Message = "Tenant OIDC provider {Provider} answered a sign-in with error {Error}.")]
    private static partial void LogProviderError(ILogger logger, string provider, string error);

    [LoggerMessage(EventId = 8604, Level = LogLevel.Information, Message = "Tenant OIDC provider {Provider} logged out {Count} session(s) through the back channel.")]
    private static partial void LogBackchannelLogout(ILogger logger, string provider, int count);

    /// <summary>What the browser's cookie holds between the start and the callback.</summary>
    private sealed record PendingSignIn(string State, string Nonce, string Verifier, string ReturnUrl, long ExpiresAt);
}

/// <summary>
/// Logout started here (RP-Initiated Logout 1.0): signing out at the token server sends a browser that signed in through a
/// tenant OIDC provider to the provider's <c>end_session_endpoint</c>, with the ID token as <c>id_token_hint</c>; the provider
/// sends it back to <c>signin/oidc/{provider}/signed-out</c>, which continues signing out here. Only for providers whose
/// discovery document has an end-session endpoint.
/// </summary>
internal sealed class TenantOidcSignOut(IServiceScopeFactory scopes, TenantOidcDocuments documents, IDataProtectionProvider dataProtection, TimeProvider time) : IExternalSignOut
{
    private static readonly TimeSpan StateLifetime = TimeSpan.FromMinutes(10);

    public async Task<string?> SignOutUrlAsync(System.Security.Claims.ClaimsPrincipal signIn, Uri requestOrigin, string returnUrl, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signIn);
        ArgumentNullException.ThrowIfNull(requestOrigin);
        if (signIn.FindFirst(TenantOidcEndpoints.ProviderClaim)?.Value is not { } provider || !TenantProviderNames.IsOidc(provider))
        {
            return null;
        }

        TenantOidcProvider? settings;
        await using (var scope = scopes.CreateAsyncScope())
        {
            settings = await scope.ServiceProvider.GetRequiredService<ITenantProviderDirectory>().FindOidcAsync(provider, cancellationToken).ConfigureAwait(false);
        }

        if (settings is null)
        {
            return null;
        }

        TenantOidcDocument document;
        try
        {
            document = await documents.GetAsync(settings.Issuer, cancellationToken).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // A provider that can't be reached is not signed out at; signing out here goes on.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            _ = exception;
            return null;
        }

        if (!Uri.TryCreate(document.Configuration.EndSessionEndpoint, UriKind.Absolute, out var endpoint) || endpoint.Scheme != Uri.UriSchemeHttps)
        {
            return null;
        }

        var state = new SignOutState(LocalRedirect.OrRoot(returnUrl), (time.GetUtcNow() + StateLifetime).ToUnixTimeSeconds());
        var query = new Dictionary<string, string>
        {
            ["client_id"] = settings.ClientId,
            ["post_logout_redirect_uri"] = new Uri(requestOrigin, $"{TenantOidcEndpoints.Prefix}/{provider}/signed-out").AbsoluteUri,
            ["state"] = Protector(dataProtection, provider).Protect(JsonSerializer.Serialize(state)),
        };
        if (signIn.FindFirst(TenantOidcEndpoints.IdTokenClaim)?.Value is { Length: > 0 } idToken)
        {
            query["id_token_hint"] = idToken;
        }

        var separator = endpoint.Query.Length > 0 ? '&' : '?';
        return endpoint.AbsoluteUri + separator + string.Join('&', query.Select(pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));
    }

    /// <summary>Where to continue after the provider logged out; null when the state is invalid or expired.</summary>
    public static string? ReadState(string? state, string provider, IDataProtectionProvider dataProtection, TimeProvider time)
    {
        if (string.IsNullOrEmpty(state))
        {
            return null;
        }

        try
        {
            var read = JsonSerializer.Deserialize<SignOutState>(Protector(dataProtection, provider).Unprotect(state));
            return read is not null && DateTimeOffset.FromUnixTimeSeconds(read.ExpiresAt) > time.GetUtcNow() ? LocalRedirect.OrRoot(read.ReturnUrl) : null;
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException)
        {
            return null;
        }
    }

    private static IDataProtector Protector(IDataProtectionProvider dataProtection, string provider) =>
        dataProtection.CreateProtector("JeffOps.Oidc.TenantSignOut.v1", provider);

    private sealed record SignOutState(string ReturnUrl, long ExpiresAt);
}

/// <summary>Sends <c>signin/tenant-oidc-{id}</c> to <c>signin/oidc/tenant-oidc-{id}</c>.</summary>
internal sealed class TenantOidcChallenge : IExternalProviderChallenge
{
    public bool Handles(string provider) => TenantProviderNames.IsOidc(provider);

    public string ChallengePath(string provider, string returnUrl, string? loginHint) =>
        $"/{TenantOidcEndpoints.Prefix}/{Uri.EscapeDataString(provider)}?returnUrl={Uri.EscapeDataString(returnUrl)}"
        + (string.IsNullOrWhiteSpace(loginHint) ? string.Empty : $"&login_hint={Uri.EscapeDataString(loginHint)}");
}

/// <summary>A tenant provider's discovery document and signing keys.</summary>
internal sealed record TenantOidcDocument(OpenIdConnectConfiguration Configuration, IReadOnlyList<SecurityKey> Keys, DateTimeOffset FetchedAt, DateTimeOffset KeysFetchedAt);

/// <summary>
/// Discovery documents and keys of tenants' issuers, read through the public-only client and kept an hour. The document must
/// name the configured issuer (OIDC Discovery §4.3), and every endpoint must be HTTPS.
/// </summary>
internal sealed class TenantOidcDocuments(IHttpClientFactory httpClients, TimeProvider time)
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromHours(1);
    private static readonly TimeSpan MinimumKeyRefresh = TimeSpan.FromMinutes(1);
    private const int MaxBytes = 512 * 1024;
    private readonly ConcurrentDictionary<string, TenantOidcDocument> _byIssuer = new(StringComparer.Ordinal);

    public async Task<TenantOidcDocument> GetAsync(Uri issuer, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        if (_byIssuer.TryGetValue(issuer.OriginalString, out var cached) && time.GetUtcNow() - cached.FetchedAt < Lifetime)
        {
            return cached;
        }

        using var client = httpClients.CreateClient(TenantOidcEndpoints.HttpClientName);
        var configuration = OpenIdConnectConfiguration.Create(await GetStringAsync(client, new Uri(issuer.OriginalString.TrimEnd('/') + "/.well-known/openid-configuration"), cancellationToken).ConfigureAwait(false));
        if (!string.Equals(configuration.Issuer?.TrimEnd('/'), issuer.OriginalString.TrimEnd('/'), StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"The discovery document names issuer '{configuration.Issuer}', not '{issuer}'.");
        }

        foreach (var endpoint in new[] { configuration.AuthorizationEndpoint, configuration.TokenEndpoint, configuration.JwksUri })
        {
            if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            {
                throw new InvalidOperationException("The discovery document must give HTTPS authorization, token and key endpoints.");
            }
        }

        if (!string.IsNullOrEmpty(configuration.UserInfoEndpoint) && !configuration.UserInfoEndpoint.StartsWith("https://", StringComparison.Ordinal))
        {
            configuration.UserInfoEndpoint = null;
        }

        var keys = await KeysAsync(client, configuration, cancellationToken).ConfigureAwait(false);
        var now = time.GetUtcNow();
        var document = new TenantOidcDocument(configuration, keys, now, now);
        _byIssuer[issuer.OriginalString] = document;
        return document;
    }

    /// <summary>Reads the keys again (an unknown key id), at most once a minute per issuer.</summary>
    public async Task<TenantOidcDocument> RefreshKeysAsync(Uri issuer, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        var current = await GetAsync(issuer, cancellationToken).ConfigureAwait(false);
        if (time.GetUtcNow() - current.KeysFetchedAt < MinimumKeyRefresh)
        {
            return current;
        }

        using var client = httpClients.CreateClient(TenantOidcEndpoints.HttpClientName);
        var refreshed = current with { Keys = await KeysAsync(client, current.Configuration, cancellationToken).ConfigureAwait(false), KeysFetchedAt = time.GetUtcNow() };
        _byIssuer[issuer.OriginalString] = refreshed;
        return refreshed;
    }

    private static async Task<IReadOnlyList<SecurityKey>> KeysAsync(HttpClient client, OpenIdConnectConfiguration configuration, CancellationToken cancellationToken)
    {
        var set = new JsonWebKeySet(await GetStringAsync(client, new Uri(configuration.JwksUri), cancellationToken).ConfigureAwait(false));
        var keys = set.GetSigningKeys();
        return keys.Count == 0 ? throw new InvalidOperationException("The provider publishes no signing keys.") : [.. keys];
    }

    private static async Task<string> GetStringAsync(HttpClient client, Uri url, CancellationToken cancellationToken)
    {
        using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return await PublicNetwork.ReadLimitedAsync(response, MaxBytes, cancellationToken).ConfigureAwait(false);
    }
}

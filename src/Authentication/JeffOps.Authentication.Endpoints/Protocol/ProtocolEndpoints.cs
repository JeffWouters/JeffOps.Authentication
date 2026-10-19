using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Features.Accounts;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Application.Features.Grants.ClientCredentials;
using JeffOps.Authentication.Application.Features.Grants.ExchangePat;
using JeffOps.Authentication.Application.Features.Sessions.EndSession;
using JeffOps.Authentication.Application.Features.Sessions.RefreshSession;
using JeffOps.Authentication.Application.Features.Sessions.StartSession;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Endpoints.Protocol;

/// <summary>
/// The OpenID Connect endpoints. OpenIddict owns the protocol (parameter validation, client authentication, PKCE, token
/// formats); these passthrough handlers decide who gets what, through the application's use cases (docs/DESIGN.md §6.1).
/// </summary>
internal static class ProtocolEndpoints
{
    public static void Map(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapMethods("connect/authorize", [HttpMethods.Get, HttpMethods.Post], AuthorizeAsync).AllowAnonymous().ExcludeFromDescription();
        endpoints.MapPost("connect/token", TokenAsync).AllowAnonymous().ExcludeFromDescription();
        endpoints.MapMethods("connect/userinfo", [HttpMethods.Get, HttpMethods.Post], UserInfoAsync).AllowAnonymous().ExcludeFromDescription();
        endpoints.MapMethods("connect/endsession", [HttpMethods.Get, HttpMethods.Post], EndSessionAsync).AllowAnonymous().ExcludeFromDescription();
        endpoints.MapMethods("connect/verify", [HttpMethods.Get, HttpMethods.Post], VerifyAsync).AllowAnonymous().DisableAntiforgery().ExcludeFromDescription();
    }

    private static async Task<IResult> AuthorizeAsync(
        HttpContext context,
        ICommandHandler<StartSessionCommand, IssuedIdentity> startSession,
        ClaimNames names,
        IOptions<TokenServerOptions> options,
        TimeProvider time)
    {
        var request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        var signInScheme = options.Value.SignInScheme;

        var signedIn = await context.AuthenticateAsync(signInScheme).ConfigureAwait(false);
        var signedInAt = SignInPrincipal.SignedInAt(signedIn.Principal, names);
        var now = time.GetUtcNow();

        // Coming back from a sign-in that prompt=login or max_age asked for: it must have happened after that time. The URL's
        // time only ever asks for more; this request's own cookie, which the browser can't forge, also settles prompt=login
        // and max_age (a pushed request keeps them, so they can't be dropped from the URL).
        var freshAfter = FreshSignIn.Parse(Single(context, FreshSignIn.Parameter), now);
        var reauthenticated = FreshSignInCookie.Read(context) is { } resumed && signedInAt >= resumed;

        // A client limited to some providers (its own app registration and consent screen at each) gets only sign-ins that came
        // through one of them: a session from another product's registration signs in again here.
        var client = ClientProviders.Find(options.Value, request.ClientId);
        var mustSignIn = !signedIn.Succeeded
            || (!reauthenticated && request.HasPromptValue(PromptValues.Login))
            || (!reauthenticated && request.MaxAge is { } maxAge && signedInAt is { } at && now - at > TimeSpan.FromSeconds(maxAge))
            || (freshAfter is { } after && (signedInAt is not { } since || since < after))
            || !ClientProviders.Allows(client, SignInPrincipal.ProviderOf(signedIn.Principal));

        IResult SignInAgain()
        {
            if (request.HasPromptValue(PromptValues.None))
            {
                return Forbid(Errors.LoginRequired, "The user is not signed in.");
            }

            // Come back here after signing in, without prompt=login / max_age, or the user would be asked again forever. In their
            // place, the time the new sign-in must follow: providers are asked to authenticate the user again, and this
            // endpoint accepts only a sign-in after it.
            var required = new[]
            {
                request.HasPromptValue(PromptValues.Login) ? now : (DateTimeOffset?)null,
                request.MaxAge is { } age ? now - TimeSpan.FromSeconds(age) : null,
                freshAfter,
            }.Max();
            var parameters = (context.Request.HasFormContentType ? context.Request.Form.AsEnumerable() : context.Request.Query)
                .Where(pair => pair.Key is not (Parameters.Prompt or Parameters.MaxAge or FreshSignIn.Parameter))
                .SelectMany(pair => pair.Value.Select(value => KeyValuePair.Create(pair.Key, value)))
                .ToList();
            if (required is { } since)
            {
                parameters.Add(KeyValuePair.Create(FreshSignIn.Parameter, (string?)since.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture)));
            }

            var returnUrl = context.Request.PathBase + context.Request.Path + QueryString.Create(parameters);
            if (required is { } mustFollow)
            {
                FreshSignInCookie.Set(context, returnUrl, mustFollow);
            }

            return Results.Challenge(new AuthenticationProperties { RedirectUri = returnUrl }, [signInScheme]);
        }

        if (mustSignIn)
        {
            return SignInAgain();
        }

        if (reauthenticated)
        {
            FreshSignInCookie.Clear(context);
        }

        if (!Guid.TryParse(signedIn.Principal!.FindFirst(names.Subject)?.Value, out var accountId))
        {
            return Forbid(Errors.AccessDenied, "The sign-in does not identify an account.");
        }

        var strength = new AuthenticationStrength(signedIn.Principal.FindAll(names.AuthenticationMethods).Select(claim => claim.Value));
        var result = await startSession.HandleAsync(
            new StartSessionCommand(accountId, strength, signedInAt ?? now, request.GetScopes(), TenantHintOf(request), SignInPrincipal.SessionId(signedIn.Principal, names)),
            context.RequestAborted).ConfigureAwait(false);

        if (result.IsFailure && result.Error.Code is GrantErrors.SessionRevoked or GrantErrors.SessionExpired)
        {
            // The browser's sign-in no longer stands (ended elsewhere, revoked, too old): forget it and sign in again.
            await context.SignOutAsync(signInScheme).ConfigureAwait(false);
            return SignInAgain();
        }

        if (result.IsFailure)
        {
            return result.Error.Type == ErrorType.Unavailable
                ? Forbid(Errors.TemporarilyUnavailable, result.Error.Message)
                : Forbid(Errors.AccessDenied, result.Error.Message, result.Error.Code);
        }

        // The owner of a pending link (a tenant provider's login waiting for confirmation) just signed in another way: attach it.
        await context.RequestServices.GetRequiredService<ICommandHandler<Application.Features.Federation.ConfirmPendingLink.ConfirmPendingLinkCommand, bool>>()
            .HandleAsync(new(accountId, SignInPrincipal.ProviderOf(signedIn.Principal)), context.RequestAborted).ConfigureAwait(false);

        // dpop_jkt (RFC 9449 section 10): the code is bound to the client's key and redeemable only with a proof of it.
        var issued = Dpop.RequestedBinding(request) is { } requestedKey ? Dpop.Bind(result.Value, requestedKey) : result.Value;
        return TokenIssuance.SignIn(issued, names, options.Value, time);
    }

    private static async Task<IResult> TokenAsync(
        HttpContext context,
        ICommandHandler<ClientCredentialsCommand, IssuedIdentity> clientCredentials,
        ICommandHandler<RefreshSessionCommand, IssuedIdentity> refreshSession,
        ICommandHandler<ExchangePatCommand, IssuedIdentity> exchangePat,
        ClaimNames names,
        IOptions<TokenServerOptions> options,
        TimeProvider time)
    {
        var request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        var cancellationToken = context.RequestAborted;

        var dpop = await Dpop.CheckAsync(context, request, options.Value, time).ConfigureAwait(false);
        if (dpop.IsFailure)
        {
            return TokenIssuance.Refuse(dpop.Error, dpop.Error.Code);
        }

        Result<IssuedIdentity> result;
        if (request.IsClientCredentialsGrantType())
        {
            result = await clientCredentials.HandleAsync(new ClientCredentialsCommand(request.ClientId!, request.GetScopes()), cancellationToken).ConfigureAwait(false);
        }
        else if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType() || request.IsDeviceCodeGrantType())
        {
            var stored = (await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme).ConfigureAwait(false)).Principal;
            if (stored is null)
            {
                return TokenIssuance.Refuse(Error.Unauthorized(GrantErrors.InvalidGrant, "The grant is no longer valid."));
            }

            // A refresh token issued with DPoP stays bound to that key (RFC 9449 section 5).
            if (stored.FindFirst(Dpop.BindingClaim)?.Value is { } boundKey && boundKey != dpop.Value)
            {
                return TokenIssuance.Refuse(Error.Unauthorized(Dpop.InvalidProof, "This grant is bound to a DPoP key; prove possession of it."), Dpop.InvalidProof);
            }

            result = await refreshSession.HandleAsync(new RefreshSessionCommand(stored, stored.GetScopes()), cancellationToken).ConfigureAwait(false);
        }
        else if (request.GrantType == options.Value.PatGrantType)
        {
            result = await exchangePat.HandleAsync(
                new ExchangePatCommand((string?)request["pat"] ?? string.Empty, request.GetScopes()),
                cancellationToken).ConfigureAwait(false);
        }
        else if (context.RequestServices.GetServices<IExtensionGrantHandler>().FirstOrDefault(handler => options.Value.ExtensionGrantType(handler.Name) == request.GrantType) is { } extension)
        {
            var actor = await ActorAsync(context, request, dpop.Value).ConfigureAwait(false);
            if (actor.IsFailure)
            {
                return TokenIssuance.Refuse(actor.Error);
            }

            result = await extension.HandleAsync(
                new ExtensionGrantRequest(request.ClientId!, request.GetScopes(), ParametersOf(request), actor.Value),
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            return TokenIssuance.Refuse(Error.Failure(Errors.UnsupportedGrantType, "The grant type is not supported."), Errors.UnsupportedGrantType);
        }

        if (result.IsFailure)
        {
            return TokenIssuance.Refuse(result.Error);
        }

        var issued = dpop.Value is { } jkt ? Dpop.Bind(result.Value, jkt) : result.Value;
        return TokenIssuance.SignIn(issued, names, options.Value, time, requestedScopes: request.GetScopes());
    }

    /// <summary>
    /// The device flow's end-user verification (RFC 8628 §3.3): a signed-in user confirms the code shown on the device. GET
    /// sends the user to the confirmation page; POST (from that page, with its antiforgery token) approves or denies. The
    /// page names the client, so a user tricked into entering someone else's code sees what they would approve.
    /// </summary>
    private static async Task<IResult> VerifyAsync(
        HttpContext context,
        ICommandHandler<StartSessionCommand, IssuedIdentity> startSession,
        IOpenIddictApplicationManager applications,
        Microsoft.AspNetCore.Antiforgery.IAntiforgery antiforgery,
        ClaimNames names,
        IOptions<TokenServerOptions> options,
        TimeProvider time)
    {
        const string Page = "/account/device";
        var code = (await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme).ConfigureAwait(false)).Principal;
        var request = context.GetOpenIddictServerRequest();
        var userCode = request?.UserCode;

        if (HttpMethods.IsGet(context.Request.Method))
        {
            if (code is null)
            {
                return Results.Redirect(string.IsNullOrEmpty(userCode) ? Page : $"{Page}?error=invalid_code");
            }

            var clientId = code.GetClaim(Claims.ClientId) ?? string.Empty;
            var application = await applications.FindByClientIdAsync(clientId, context.RequestAborted).ConfigureAwait(false);
            var client = application is null ? null : await applications.GetDisplayNameAsync(application, context.RequestAborted).ConfigureAwait(false);
            var ticket = new DeviceConsentTicket(userCode ?? string.Empty, clientId, client ?? clientId).Serialize();
            var consent = Consent(context).Protect(ticket, DeviceConsentTicket.Lifetime);
            return Results.Redirect($"{Page}?user_code={Uri.EscapeDataString(userCode ?? string.Empty)}&consent={Uri.EscapeDataString(consent)}");
        }

        if (!await antiforgery.IsRequestValidAsync(context).ConfigureAwait(false))
        {
            return TypedResults.BadRequest();
        }

        if (code is null)
        {
            return Results.Redirect($"{Page}?error=invalid_code");
        }

        // The user must have seen this code's own client named: otherwise show the confirmation again, with the right name.
        if (!ConsentShown(context, userCode, code.GetClaim(Claims.ClientId)))
        {
            return Results.Redirect($"/connect/verify?user_code={Uri.EscapeDataString(userCode ?? string.Empty)}");
        }

        var signInScheme = options.Value.SignInScheme;
        var signedIn = await context.AuthenticateAsync(signInScheme).ConfigureAwait(false);
        if (!signedIn.Succeeded || !Guid.TryParse(signedIn.Principal?.FindFirst(names.Subject)?.Value, out var accountId))
        {
            return Results.Challenge(new AuthenticationProperties { RedirectUri = $"{Page}?user_code={Uri.EscapeDataString(userCode ?? string.Empty)}" }, [signInScheme]);
        }

        if (!string.Equals(context.Request.Form["decision"], "approve", StringComparison.Ordinal))
        {
            return Results.Forbid(new AuthenticationProperties { RedirectUri = $"{Page}?result=denied" }, [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        var strength = new AuthenticationStrength(signedIn.Principal!.FindAll(names.AuthenticationMethods).Select(claim => claim.Value));
        var session = await startSession.HandleAsync(
            new StartSessionCommand(accountId, strength, SignInPrincipal.SignedInAt(signedIn.Principal, names) ?? time.GetUtcNow(), code.GetScopes(), null, SignInPrincipal.SessionId(signedIn.Principal, names)),
            context.RequestAborted).ConfigureAwait(false);
        if (session.IsFailure)
        {
            return Results.Redirect($"{Page}?error={Uri.EscapeDataString(session.Error.Code)}");
        }

        return TokenIssuance.SignIn(session.Value, names, options.Value, time,
            new AuthenticationProperties { RedirectUri = $"{Page}?result=approved" });
    }

    private static async Task<IResult> UserInfoAsync(
        HttpContext context,
        IQueryHandler<GetAccountContactQuery, AccountContact> contacts,
        ClaimNames names)
    {
        var principal = (await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme).ConfigureAwait(false)).Principal;
        if (!Guid.TryParse(principal?.FindFirst(names.Subject)?.Value, out var accountId))
        {
            return Challenge(Errors.InvalidToken, "The access token does not identify an account.");
        }

        var contact = await contacts.HandleAsync(new GetAccountContactQuery(accountId), context.RequestAborted).ConfigureAwait(false);
        if (contact.IsFailure)
        {
            return Challenge(Errors.InvalidToken, "The account no longer exists.");
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal) { [Claims.Subject] = accountId.ToString() };
        if (principal!.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = contact.Value.Email;
            claims[Claims.EmailVerified] = contact.Value.EmailVerified;
        }

        if (principal.HasScope(Scopes.Profile) && !string.IsNullOrEmpty(contact.Value.DisplayName))
        {
            claims[Claims.Name] = contact.Value.DisplayName;
        }

        return Results.Ok(claims);
    }

    private static async Task<IResult> EndSessionAsync(
        HttpContext context,
        ICommandHandler<EndSessionCommand> endSession,
        IEnumerable<Application.Federation.IExternalSignOut> externalSignOuts,
        ClaimNames names,
        IOptions<TokenServerOptions> options)
    {
        // End this sign-in session everywhere it reached: its refresh tokens stop working and clients are told (sid).
        var signedIn = await context.AuthenticateAsync(options.Value.SignInScheme).ConfigureAwait(false);
        if (signedIn.Succeeded && Guid.TryParse(signedIn.Principal.FindFirst(names.Subject)?.Value, out var accountId)
            && SignInPrincipal.SessionId(signedIn.Principal, names) is { } sessionId)
        {
            await endSession.HandleAsync(new EndSessionCommand(accountId, sessionId), context.RequestAborted).ConfigureAwait(false);
        }

        // Signed in through a provider with single logout: sign out there too, then come back here to finish (signed out
        // locally by then, so the second pass completes the end-session request).
        if (signedIn.Succeeded)
        {
            var origin = new Uri($"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/");
            var returnUrl = context.Request.PathBase + context.Request.Path + QueryString.Create(
                (context.Request.HasFormContentType ? context.Request.Form.AsEnumerable() : context.Request.Query.AsEnumerable())
                    .Where(pair => pair.Key != "__RequestVerificationToken")
                    .SelectMany(pair => pair.Value.Select(value => KeyValuePair.Create(pair.Key, value))));
            foreach (var externalSignOut in externalSignOuts)
            {
                if (await externalSignOut.SignOutUrlAsync(signedIn.Principal, origin, returnUrl, context.RequestAborted).ConfigureAwait(false) is { } url)
                {
                    await context.SignOutAsync(options.Value.SignInScheme).ConfigureAwait(false);
                    return Results.Redirect(url);
                }
            }
        }

        await context.SignOutAsync(options.Value.SignInScheme).ConfigureAwait(false);

        // OpenIddict redirects to the validated post_logout_redirect_uri, or to the RedirectUri below without one.
        return Results.SignOut(new AuthenticationProperties { RedirectUri = "/" }, [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    /// <summary>A parameter of the authorize request as the browser sent it (query or form), when given once.</summary>
    private static string? Single(HttpContext context, string name) =>
        (context.Request.HasFormContentType ? context.Request.Form[name] : context.Request.Query[name]) is { Count: 1 } values ? values[0] : null;

    private static ITimeLimitedDataProtector Consent(HttpContext context) =>
        context.RequestServices.GetRequiredService<IDataProtectionProvider>().CreateProtector(DeviceConsentTicket.Purpose).ToTimeLimitedDataProtector();

    /// <summary>Whether the posted consent ticket is the token server's, for this user code and the code's own client.</summary>
    private static bool ConsentShown(HttpContext context, string? userCode, string? clientId)
    {
        string json;
        try
        {
            json = Consent(context).Unprotect(context.Request.Form["consent"].ToString());
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return false;
        }

        return DeviceConsentTicket.Deserialize(json) is { } ticket
            && string.Equals(ticket.UserCode, userCode, StringComparison.Ordinal)
            && string.Equals(ticket.ClientId, clientId, StringComparison.Ordinal);
    }

    /// <summary>
    /// Validates the request's <c>actor_token</c> (RFC 8693 §2.1), which must be a live access token this server issued to the
    /// requesting client, covering every requested scope, and — when it is DPoP-bound — presented with a proof of its key on
    /// this request. So a token that leaked to an API or another client can't be traded for a new, broader or unbound one. A
    /// missing actor token is not an error here; the grant decides whether it needs one.
    /// </summary>
    private static async Task<Result<System.Security.Claims.ClaimsPrincipal?>> ActorAsync(HttpContext context, OpenIddictRequest request, string? proofKey)
    {
        if (string.IsNullOrEmpty(request.ActorToken))
        {
            return Result.Success<System.Security.Claims.ClaimsPrincipal?>(null);
        }

        if (request.ActorTokenType is { } type && type != TokenTypeIdentifiers.AccessToken)
        {
            return Error.Unauthorized(GrantErrors.TokenInvalid, "The actor token must be an access token.");
        }

        try
        {
            var validation = context.RequestServices.GetRequiredService<OpenIddict.Validation.OpenIddictValidationService>();
            var actor = await validation.ValidateAccessTokenAsync(request.ActorToken, context.RequestAborted).ConfigureAwait(false);

            if (!string.Equals(actor.GetClaim(Claims.ClientId), request.ClientId, StringComparison.Ordinal))
            {
                return Error.Unauthorized(GrantErrors.TokenInvalid, "The actor token was issued to another client.");
            }

            var held = actor.GetScopes();
            if (request.GetScopes().Any(scope => !held.Contains(scope, StringComparer.Ordinal)))
            {
                return Error.Unauthorized(GrantErrors.TokenInvalid, "The actor token doesn't cover the requested scopes.");
            }

            var (bound, jkt) = DpopBinding.Of(actor);
            if (bound && (jkt is null || !string.Equals(jkt, proofKey, StringComparison.Ordinal)))
            {
                return Error.Unauthorized(Dpop.InvalidProof, "The actor token is DPoP-bound; prove possession of its key on this request.");
            }

            return actor;
        }
        catch (OpenIddict.Abstractions.OpenIddictExceptions.ProtocolException)
        {
            return Error.Unauthorized(GrantErrors.TokenInvalid, "The actor token is invalid or expired.");
        }
    }

    private static Dictionary<string, string?> ParametersOf(OpenIddictRequest request) =>
        request.GetParameters()
            .Where(pair => pair.Key is not (Parameters.ClientSecret or Parameters.ActorToken or Parameters.SubjectToken))
            .ToDictionary(pair => pair.Key, pair => (string?)pair.Value, StringComparer.Ordinal);

    private static Guid? TenantHintOf(OpenIddictRequest request) =>
        Guid.TryParse((string?)request["tenant_hint"], out var tenant) ? tenant : null;

    private static IResult Forbid(string error, string description, string? code = null)
    {
        var properties = new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        });
        if (code is not null)
        {
            properties.Parameters[TokenIssuance.CodeParameter] = code;
        }

        return Results.Forbid(properties, [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    private static IResult Challenge(string error, string description) =>
        Results.Challenge(
            new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
            }),
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
}

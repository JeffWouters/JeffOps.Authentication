using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Features.Accounts;
using JeffOps.Authentication.Application.Features.Grants.ClientCredentials;
using JeffOps.Authentication.Application.Features.Grants.ExchangePat;
using JeffOps.Authentication.Application.Features.Sessions.RefreshSession;
using JeffOps.Authentication.Application.Features.Sessions.StartSession;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
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
        IOpenIddictScopeManager scopeManager,
        ClaimNames names,
        IOptions<TokenServerOptions> options,
        TimeProvider time)
    {
        var request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");
        var signInScheme = options.Value.SignInScheme;

        var signedIn = await context.AuthenticateAsync(signInScheme).ConfigureAwait(false);
        var signedInAt = SignInPrincipal.SignedInAt(signedIn.Principal, names);

        var mustSignIn = !signedIn.Succeeded
            || request.HasPromptValue(PromptValues.Login)
            || (request.MaxAge is { } maxAge && signedInAt is { } at && time.GetUtcNow() - at > TimeSpan.FromSeconds(maxAge));

        if (mustSignIn)
        {
            if (request.HasPromptValue(PromptValues.None))
            {
                return Forbid(Errors.LoginRequired, "The user is not signed in.");
            }

            // Come back here after signing in, without prompt=login / max_age, or the user would be asked again forever.
            var parameters = context.Request.HasFormContentType
                ? context.Request.Form.Where(pair => pair.Key is not (Parameters.Prompt or Parameters.MaxAge))
                : context.Request.Query.Where(pair => pair.Key is not (Parameters.Prompt or Parameters.MaxAge));
            var returnUrl = context.Request.PathBase + context.Request.Path
                + QueryString.Create(parameters.SelectMany(pair => pair.Value.Select(value => KeyValuePair.Create(pair.Key, value))));

            return Results.Challenge(new AuthenticationProperties { RedirectUri = returnUrl }, [signInScheme]);
        }

        if (!Guid.TryParse(signedIn.Principal!.FindFirst(names.Subject)?.Value, out var accountId))
        {
            return Forbid(Errors.AccessDenied, "The sign-in does not identify an account.");
        }

        var strength = new AuthenticationStrength(signedIn.Principal.FindAll(names.AuthenticationMethods).Select(claim => claim.Value));
        var result = await startSession.HandleAsync(
            new StartSessionCommand(accountId, strength, signedInAt ?? time.GetUtcNow(), request.GetScopes(), TenantHintOf(request)),
            context.RequestAborted).ConfigureAwait(false);

        if (result.IsFailure)
        {
            return result.Error.Type == ErrorType.Unavailable
                ? Forbid(Errors.TemporarilyUnavailable, result.Error.Message)
                : Forbid(Errors.AccessDenied, result.Error.Message, result.Error.Code);
        }

        // dpop_jkt (RFC 9449 section 10): the code is bound to the client's key and redeemable only with a proof of it.
        var issued = Dpop.RequestedBinding(request) is { } requestedKey ? Dpop.Bind(result.Value, requestedKey) : result.Value;
        return await TokenIssuance.SignInAsync(issued, names, scopeManager, time, context.RequestAborted).ConfigureAwait(false);
    }

    private static async Task<IResult> TokenAsync(
        HttpContext context,
        ICommandHandler<ClientCredentialsCommand, IssuedIdentity> clientCredentials,
        ICommandHandler<RefreshSessionCommand, IssuedIdentity> refreshSession,
        ICommandHandler<ExchangePatCommand, IssuedIdentity> exchangePat,
        IOpenIddictScopeManager scopeManager,
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
        return await TokenIssuance.SignInAsync(issued, names, scopeManager, time, cancellationToken).ConfigureAwait(false);
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
        IOpenIddictScopeManager scopeManager,
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

            var application = await applications.FindByClientIdAsync(code.GetClaim(Claims.ClientId) ?? string.Empty, context.RequestAborted).ConfigureAwait(false);
            var client = application is null ? "an application" : await applications.GetDisplayNameAsync(application, context.RequestAborted).ConfigureAwait(false);
            return Results.Redirect($"{Page}?user_code={Uri.EscapeDataString(userCode ?? string.Empty)}&client={Uri.EscapeDataString(client ?? "an application")}");
        }

        if (!await antiforgery.IsRequestValidAsync(context).ConfigureAwait(false))
        {
            return TypedResults.BadRequest();
        }

        if (code is null)
        {
            return Results.Redirect($"{Page}?error=invalid_code");
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
            new StartSessionCommand(accountId, strength, SignInPrincipal.SignedInAt(signedIn.Principal, names) ?? time.GetUtcNow(), code.GetScopes(), null),
            context.RequestAborted).ConfigureAwait(false);
        if (session.IsFailure)
        {
            return Results.Redirect($"{Page}?error={Uri.EscapeDataString(session.Error.Code)}");
        }

        return await TokenIssuance.SignInAsync(session.Value, names, scopeManager, time, context.RequestAborted,
            new AuthenticationProperties { RedirectUri = $"{Page}?result=approved" }).ConfigureAwait(false);
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

    private static async Task<IResult> EndSessionAsync(HttpContext context, IOptions<TokenServerOptions> options)
    {
        await context.SignOutAsync(options.Value.SignInScheme).ConfigureAwait(false);

        // OpenIddict redirects to the validated post_logout_redirect_uri, or to the RedirectUri below without one.
        return Results.SignOut(new AuthenticationProperties { RedirectUri = "/" }, [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
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

using System.Globalization;
using System.Security.Claims;
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

        return await TokenIssuance.SignInAsync(result.Value, names, scopeManager, time, context.RequestAborted).ConfigureAwait(false);
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

        Result<IssuedIdentity> result;
        if (request.IsClientCredentialsGrantType())
        {
            result = await clientCredentials.HandleAsync(new ClientCredentialsCommand(request.ClientId!, request.GetScopes()), cancellationToken).ConfigureAwait(false);
        }
        else if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            var stored = (await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme).ConfigureAwait(false)).Principal;
            if (stored is null)
            {
                return TokenIssuance.Refuse(Error.Unauthorized(GrantErrors.InvalidGrant, "The grant is no longer valid."));
            }

            result = await refreshSession.HandleAsync(new RefreshSessionCommand(stored, stored.GetScopes()), cancellationToken).ConfigureAwait(false);
        }
        else if (request.GrantType == options.Value.PatGrantType)
        {
            result = await exchangePat.HandleAsync(
                new ExchangePatCommand((string?)request["pat"] ?? string.Empty, request.GetScopes()),
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            return TokenIssuance.Refuse(Error.Failure(Errors.UnsupportedGrantType, "The grant type is not supported."), Errors.UnsupportedGrantType);
        }

        return result.IsSuccess
            ? await TokenIssuance.SignInAsync(result.Value, names, scopeManager, time, cancellationToken).ConfigureAwait(false)
            : TokenIssuance.Refuse(result.Error);
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

/// <summary>
/// The principal the login UI or a federation callback signs in with the sign-in scheme. The authorize endpoint reads it:
/// the account id, how the user authenticated, and when. Use <see cref="Create"/> so the claims match.
/// </summary>
public static class SignInPrincipal
{
    public static ClaimsPrincipal Create(Guid accountId, AuthenticationStrength strength, DateTimeOffset signedInAt, ClaimNames names, string authenticationType)
    {
        ArgumentNullException.ThrowIfNull(strength);
        ArgumentNullException.ThrowIfNull(names);

        var claims = new List<Claim>
        {
            new(names.Subject, accountId.ToString()),
            new(names.AuthenticationTime, signedInAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
        };
        claims.AddRange(strength.Methods.Select(method => new Claim(names.AuthenticationMethods, method)));

        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType, names.Name, "role"));
    }

    public static DateTimeOffset? SignedInAt(ClaimsPrincipal? principal, ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(names);
        return long.TryParse(principal?.FindFirst(names.AuthenticationTime)?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
    }
}

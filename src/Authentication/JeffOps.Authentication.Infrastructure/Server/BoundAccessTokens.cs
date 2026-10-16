using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Dpop;
using JeffOps.Authentication.Abstractions.Replay;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation;
using OpenIddict.Validation.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// DPoP for the token server's own APIs (RFC 9449 §7): access tokens are read from <c>Authorization: DPoP</c> as well as
/// <c>Bearer</c>, and a token bound to a key (<c>cnf.jkt</c>) counts only with a fresh, unused proof of that key for the
/// request. A bound token sent as a bearer token is refused, so a stolen one is useless without the client's private key —
/// here as at resource services.
/// </summary>
internal static class BoundAccessTokens
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    /// <summary>Reads access tokens sent with the DPoP scheme and checks bound tokens, for OpenIddict validation.</summary>
    public static void Register(OpenIddictValidationBuilder validation)
    {
        // OpenIddict's own proof-of-possession check knows only mTLS bindings and throws on cnf.jkt; the handlers below
        // check DPoP bindings and refuse any other kind.
        validation.RemoveEventHandler(OpenIddictValidationHandlers.Protection.ValidateProofOfPossession.Descriptor);
        validation.AddEventHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>(handler => handler
            .UseInlineHandler(context =>
            {
                if (context.ExtractAccessToken && string.IsNullOrEmpty(context.AccessToken)
                    && context.Transaction.GetHttpRequest() is { } request && FromDpopScheme(request) is { } token)
                {
                    context.AccessToken = token;
                }

                return default;
            })
            .SetOrder(OpenIddictValidationAspNetCoreHandlers.ExtractAccessTokenFromAuthorizationHeader.Descriptor.Order + 1)
            .SetType(OpenIddictValidationHandlerType.Custom));

        validation.AddEventHandler<OpenIddictValidationEvents.ProcessAuthenticationContext>(handler => handler
            .UseInlineHandler(async context =>
            {
                if (context.AccessTokenPrincipal is { } principal && context.AccessToken is { } token
                    && context.Transaction.GetHttpRequest() is { } request && await CheckAsync(request, principal, token).ConfigureAwait(false) is { } failure)
                {
                    context.Reject(Errors.InvalidToken, failure);
                }
            })
            .SetOrder(OpenIddictValidationHandlers.ValidateAccessToken.Descriptor.Order + 1_000)
            .SetType(OpenIddictValidationHandlerType.Custom));
    }

    /// <summary>The same for the server's userinfo endpoint, which OpenIddict server authenticates itself.</summary>
    public static void Register(OpenIddictServerBuilder server)
    {
        server.RemoveEventHandler(OpenIddictServerHandlers.Protection.ValidateProofOfPossession.Descriptor);
        server.AddEventHandler<OpenIddictServerEvents.ExtractUserInfoRequestContext>(handler => handler
            .UseInlineHandler(context =>
            {
                if (context.Request is { } request && string.IsNullOrEmpty(request.AccessToken)
                    && context.Transaction.GetHttpRequest() is { } http && FromDpopScheme(http) is { } token)
                {
                    request.AccessToken = token;
                }

                return default;
            })
            .SetOrder(OpenIddictServerAspNetCoreHandlers.ExtractAccessToken<OpenIddictServerEvents.ExtractUserInfoRequestContext>.Descriptor.Order + 1)
            .SetType(OpenIddictServerHandlerType.Custom));

        server.AddEventHandler<OpenIddictServerEvents.ProcessAuthenticationContext>(handler => handler
            .UseInlineHandler(async context =>
            {
                if (context.EndpointType == OpenIddictServerEndpointType.UserInfo
                    && context.AccessTokenPrincipal is { } principal && context.AccessToken is { } token
                    && context.Transaction.GetHttpRequest() is { } request && await CheckAsync(request, principal, token).ConfigureAwait(false) is { } failure)
                {
                    context.Reject(Errors.InvalidToken, failure);
                }
            })
            .SetOrder(OpenIddictServerHandlers.ValidateAccessToken.Descriptor.Order + 1_000)
            .SetType(OpenIddictServerHandlerType.Custom));
    }

    /// <summary>Why the request may not use this access token, or null when it may.</summary>
    public static async Task<string?> CheckAsync(HttpRequest request, ClaimsPrincipal principal, string accessToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var usedDpopScheme = FromDpopScheme(request) is not null;
        var (bound, jkt) = Application.Sessions.DpopBinding.Of(principal);
        if (!bound)
        {
            return usedDpopScheme ? "The token is not DPoP-bound." : null;
        }

        if (jkt is null)
        {
            return "The token's key binding is not supported.";
        }

        if (!usedDpopScheme)
        {
            return "A DPoP-bound token must be sent with the DPoP scheme.";
        }

        var proofs = request.Headers[DpopProofValidator.HeaderName];
        if (proofs.Count != 1)
        {
            return "Send exactly one DPoP proof.";
        }

        var services = request.HttpContext.RequestServices;
        var now = services.GetRequiredService<TimeProvider>().GetUtcNow();
        var target = new Uri($"{request.Scheme}://{request.Host}{request.PathBase}{request.Path}");
        var (proof, error) = DpopProofValidator.Validate(proofs[0], request.Method, target, now, Window, accessToken);
        if (proof is null)
        {
            return error;
        }

        if (!string.Equals(proof.Jkt, jkt, StringComparison.Ordinal))
        {
            return "The DPoP proof is signed by another key than the token is bound to.";
        }

        return await services.GetRequiredService<IReplayCache>()
                .TryAddAsync(ReplayKeys.For("dpop", proof.Jkt + "\n" + proof.Jti), now + Window + Window, request.HttpContext.RequestAborted).ConfigureAwait(false)
            ? null
            : "This DPoP proof was already used.";
    }

    private static string? FromDpopScheme(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString();
        return header.StartsWith(DpopProofValidator.Scheme + " ", StringComparison.OrdinalIgnoreCase)
            ? header[(DpopProofValidator.Scheme.Length + 1)..].Trim() is { Length: > 0 } token ? token : null
            : null;
    }
}

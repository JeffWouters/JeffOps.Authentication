using System.Collections.Immutable;
using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Endpoints.Protocol;

/// <summary>Turns an <see cref="IssuedIdentity"/> into an OpenIddict sign-in, and a refusal into an OAuth error.</summary>
internal static class TokenIssuance
{
    /// <summary>The extra response parameter carrying the refusal's stable code (for example <c>mfa_required</c>).</summary>
    public const string CodeParameter = "code";

    /// <summary>
    /// Signs <paramref name="issued"/> in with OpenIddict. The token's resources (audiences) come from
    /// <see cref="Application.TokenServerOptions.ApiScopes"/>, the configuration the scope store is seeded from at startup, so no
    /// request reads the scope store for them.
    /// </summary>
    public static IResult SignIn(
        IssuedIdentity issued,
        ClaimNames names,
        Application.TokenServerOptions options,
        TimeProvider time,
        AuthenticationProperties? properties = null)
    {
        var scopes = issued.AllowRefresh
            ? issued.Scopes.ToImmutableArray()
            : issued.Scopes.Where(scope => scope != Scopes.OfflineAccess).ToImmutableArray();

        var identity = new ClaimsIdentity(issued.Claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, names.Name, "role");
        identity.SetScopes(scopes);

        var resources = scopes
            .SelectMany(scope => options.ApiScopes.TryGetValue(scope, out var audiences) ? audiences : [])
            .Where(audience => !string.IsNullOrWhiteSpace(audience))
            .Distinct(StringComparer.Ordinal);
        identity.SetResources(resources);
        identity.SetDestinations(claim => DestinationsOf(claim, names, scopes));

        var principal = new ClaimsPrincipal(identity);
        if (issued.AccessTokenLifetime is { } accessLifetime)
        {
            principal.SetAccessTokenLifetime(accessLifetime);
        }

        if (issued.SessionEndsAt is { } ends)
        {
            // The refresh token never outlives the session's absolute lifetime.
            var remaining = ends - time.GetUtcNow();
            principal.SetRefreshTokenLifetime(remaining > TimeSpan.Zero ? remaining : TimeSpan.FromSeconds(1));
        }

        return Results.SignIn(principal, properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// A refusal at the token endpoint: <c>invalid_grant</c> (or <c>server_error</c> when a dependency is unavailable, so the
    /// client retries instead of signing the user out), with the stable code as an extra parameter.
    /// </summary>
    public static IResult Refuse(Error error, string? oauthError = null)
    {
        ArgumentNullException.ThrowIfNull(error);

        var properties = new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = oauthError ?? (error.Type == ErrorType.Unavailable ? Errors.ServerError : Errors.InvalidGrant),
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = error.Message,
        });
        properties.Parameters[CodeParameter] = error.Code;

        return Results.Forbid(properties, [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    private static IEnumerable<string> DestinationsOf(Claim claim, ClaimNames names, ImmutableArray<string> scopes)
    {
        yield return Destinations.AccessToken;

        // The DPoP binding goes to the access token only, where token generation turns it into cnf.jkt.
        if (claim.Type == Dpop.BindingClaim)
        {
            yield break;
        }

        var inIdentityToken =
            claim.Type == names.Subject
            || claim.Type == names.AuthenticationMethods
            || claim.Type == names.AuthenticationTime
            || claim.Type == names.SessionId
            || (claim.Type == names.Email && scopes.Contains(Scopes.Email))
            || (claim.Type == names.Name && scopes.Contains(Scopes.Profile));

        if (inIdentityToken)
        {
            yield return Destinations.IdentityToken;
        }
    }
}

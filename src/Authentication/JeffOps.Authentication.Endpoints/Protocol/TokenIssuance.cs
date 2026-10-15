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

    public static async Task<IResult> SignInAsync(IssuedIdentity issued, ClaimNames names, IOpenIddictScopeManager scopeManager, TimeProvider time, CancellationToken cancellationToken)
    {
        var scopes = issued.AllowRefresh
            ? issued.Scopes.ToImmutableArray()
            : issued.Scopes.Where(scope => scope != Scopes.OfflineAccess).ToImmutableArray();

        var identity = new ClaimsIdentity(issued.Claims, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, names.Name, "role");
        identity.SetScopes(scopes);

        var resources = new List<string>();
        await foreach (var resource in scopeManager.ListResourcesAsync(scopes, cancellationToken).ConfigureAwait(false))
        {
            resources.Add(resource);
        }

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

        return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
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

        var inIdentityToken =
            claim.Type == names.Subject
            || claim.Type == names.AuthenticationMethods
            || claim.Type == names.AuthenticationTime
            || (claim.Type == names.Email && scopes.Contains(Scopes.Email))
            || (claim.Type == names.Name && scopes.Contains(Scopes.Profile));

        if (inIdentityToken)
        {
            yield return Destinations.IdentityToken;
        }
    }
}

using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using ITfoxtec.Identity.Saml2;
using JeffOps.Authentication.Abstractions.Http;
using JeffOps.Authentication.Application.Federation;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace JeffOps.Authentication.Federation.Saml;

/// <summary>
/// Single logout started here (SP-initiated): signing out at the token server sends the browser to the identity provider
/// with a signed LogoutRequest naming the user and their session there (NameID, SessionIndex). The provider answers at
/// <c>signin/saml/{provider}/slo</c>, and the browser goes back to finish signing out. Only for providers with a single
/// logout URL and a signing certificate here (providers require signed logout requests).
/// </summary>
internal sealed class SamlSignOut(IServiceScopeFactory scopes) : IExternalSignOut
{
    public const string ProviderClaim = "jeffops:saml:provider";
    public const string NameIdClaim = "jeffops:saml:name_id";
    public const string NameIdFormatClaim = "jeffops:saml:name_id_format";
    public const string SessionIndexClaim = "jeffops:saml:session_index";

    private static readonly TimeSpan RelayLifetime = TimeSpan.FromMinutes(10);

    public async Task<string?> SignOutUrlAsync(ClaimsPrincipal signIn, Uri requestOrigin, string returnUrl, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(signIn);
        if (signIn.FindFirst(ProviderClaim)?.Value is not { } provider || signIn.FindFirst(NameIdClaim)?.Value is not { } nameId)
        {
            return null;
        }

        await using var scope = scopes.CreateAsyncScope();
        var saml = scope.ServiceProvider.GetRequiredService<SamlServices>();
        if (!await saml.Providers.PrepareAsync(provider, cancellationToken).ConfigureAwait(false)
            || saml.Providers.SingleLogoutUrl(provider) is not { } logoutUrl || saml.Providers.SigningCertificate(provider) is null)
        {
            return null;
        }

        var entityId = saml.Providers.ServiceProviderEntityId(provider, saml.TokenServer, requestOrigin);
        var request = new Saml2LogoutRequest(saml.Providers.Configuration(provider, entityId, saml.ReplayCache))
        {
            NameId = new Saml2NameIdentifier(nameId, signIn.FindFirst(NameIdFormatClaim)?.Value is { } format ? new Uri(format) : null),
            SessionIndex = signIn.FindFirst(SessionIndexClaim)?.Value,
            Destination = logoutUrl,
        };

        var expires = saml.Time.GetUtcNow() + RelayLifetime;
        var binding = new Saml2RedirectBinding
        {
            RelayState = saml.Protector.Protect(string.Create(CultureInfo.InvariantCulture,
                $"{request.IdAsString}|{expires.ToUnixTimeSeconds()}|{LocalRedirect.OrRoot(returnUrl)}")),
        };
        binding.Bind(request);
        return binding.RedirectLocation.OriginalString;
    }

    /// <summary>The logout request a RelayState stands for and where to go back to; null when it's invalid or expired.</summary>
    public static (string RequestId, string ReturnUrl)? ReadRelayState(string? relayState, SamlServices saml)
    {
        if (string.IsNullOrEmpty(relayState))
        {
            return null;
        }

        try
        {
            var parts = saml.Protector.Unprotect(relayState).Split('|', 3);
            return parts.Length == 3 && long.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var expires)
                && DateTimeOffset.FromUnixTimeSeconds(expires) > saml.Time.GetUtcNow()
                ? (parts[0], LocalRedirect.OrRoot(parts[2]))
                : null;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}

using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Claims;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Federation.Saml;

/// <summary>The SAML providers this server knows, by name.</summary>
public sealed record SamlProviderRegistration(string Name);

/// <summary>
/// Lists the SAML providers on the login page, starts their sign-in, and turns a validated SAML assertion into an
/// <see cref="ExternalIdentity"/> linked by (IdP entity id, NameID).
/// </summary>
internal sealed class SamlProviders(
    IEnumerable<SamlProviderRegistration> registrations,
    IOptionsMonitor<SamlProviderOptions> options,
    IOptions<SamlTenantProviderOptions> tenantDefaults,
    SamlMetadata metadata,
    SamlMetadataClient metadataClient,
    IServiceScopeFactory scopes,
    TimeProvider time) : IExternalIdentityMapper, IExternalProviderChallenge
{
    private static readonly TimeSpan TenantSettingsLifetime = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, (SamlProviderOptions Settings, DateTimeOffset LoadedAt)> _tenants = new(StringComparer.Ordinal);
    private readonly Lazy<(X509Certificate2? Signing, X509Certificate2? Decryption)> _tenantCertificates = new(() =>
        (LoadPfx(tenantDefaults.Value.SigningCertificatePfx, tenantDefaults.Value.SigningCertificatePassword),
         LoadPfx(tenantDefaults.Value.DecryptionCertificatePfx, tenantDefaults.Value.DecryptionCertificatePassword)));

    /// <summary>The claim the ACS endpoint adds with the authentication context class reference.</summary>
    public const string AuthnContextClaim = "jeffops:saml:authn_context";

    public IReadOnlyCollection<ExternalProviderInfo> Providers =>
        [.. registrations.Select(registration => new ExternalProviderInfo(registration.Name, options.Get(registration.Name).DisplayName ?? registration.Name))];

    public bool Handles(string provider) => IsConfigured(provider) || IsTenantName(provider);

    /// <summary>
    /// Makes <paramref name="provider"/>'s settings available to <see cref="Settings"/>: configured providers always are; a
    /// provider a tenant registered is read from its directory (at most a minute old), with its metadata unless
    /// <paramref name="withMetadata"/> is false. False when there is no such provider, or its tenant may no longer use it.
    /// </summary>
    public async Task<bool> PrepareAsync(string provider, CancellationToken cancellationToken, bool withMetadata = true)
    {
        if (IsConfigured(provider))
        {
            return true;
        }

        if (!IsTenantName(provider))
        {
            return false;
        }

        if (_tenants.TryGetValue(provider, out var cached) && time.GetUtcNow() - cached.LoadedAt < TenantSettingsLifetime)
        {
            if (withMetadata)
            {
                await metadataClient.EnsureAsync(provider, cached.Settings, cancellationToken).ConfigureAwait(false);
            }

            return true;
        }

        TenantSamlProvider? found;
        await using (var scope = scopes.CreateAsyncScope())
        {
            found = await scope.ServiceProvider.GetRequiredService<ITenantProviderDirectory>().FindSamlAsync(provider, cancellationToken).ConfigureAwait(false);
        }

        if (found is null)
        {
            _tenants.TryRemove(provider, out _);
            metadata.Remove(provider);
            return false;
        }

        var settings = new SamlProviderOptions
        {
            DisplayName = found.DisplayName,
            IdpEntityId = found.IdpEntityId,
            IdpMetadataUrl = found.MetadataUrl,
            IdpSingleSignOnUrl = found.SingleSignOnUrl,
            IdpSingleLogoutUrl = found.SingleLogoutUrl,
            OwnerTenantId = found.TenantId,
            LoginIssuer = "urn:jeffops:tenant-provider:" + provider[TenantProviderNames.Prefix.Length..],

            // The tenant owns the domain the address is in (checked at every sign-in), so its provider vouches for it.
            EmailVerified = true,
            SigningCertificate = _tenantCertificates.Value.Signing,
            DecryptionCertificate = _tenantCertificates.Value.Decryption,
        };
        foreach (var certificate in found.SigningCertificates)
        {
            settings.IdpSigningCertificates.Add(certificate);
        }

        foreach (var context in found.MultiFactorAuthnContexts)
        {
            settings.MultiFactorAuthnContexts.Add(context);
        }

        _tenants[provider] = (settings, time.GetUtcNow());
        if (withMetadata)
        {
            await metadataClient.EnsureAsync(provider, settings, cancellationToken).ConfigureAwait(false);
        }

        return true;
    }

    /// <summary>
    /// Whether anything can verify the provider's signatures: configured certificates, or current metadata. A provider
    /// without is refused at every endpoint (its messages couldn't be checked, and an unsigned one would pass).
    /// </summary>
    public bool HasTrustAnchors(string provider)
    {
        var settings = Settings(provider);
        return settings.IdpSigningCertificates.Count > 0 || metadata.For(provider, settings) is { SigningCertificates.Count: > 0 };
    }

    /// <summary>The settings of a provider (after <see cref="PrepareAsync"/> for one a tenant registered).</summary>
    public SamlProviderOptions Settings(string provider) =>
        IsTenantName(provider)
            ? _tenants.TryGetValue(provider, out var cached) ? cached.Settings : new SamlProviderOptions()
            : options.Get(provider);

    private bool IsConfigured(string provider) => registrations.Any(registration => string.Equals(registration.Name, provider, StringComparison.Ordinal));

    private static bool IsTenantName(string provider) => TenantProviderNames.IsSaml(provider);

    public string ChallengePath(string provider, string returnUrl, string? loginHint) =>
        $"/{SamlEndpoints.Prefix}/{Uri.EscapeDataString(provider)}?returnUrl={Uri.EscapeDataString(returnUrl)}"
        + (string.IsNullOrWhiteSpace(loginHint) ? string.Empty : $"&login_hint={Uri.EscapeDataString(loginHint)}");

    public Result<ExternalIdentity> Map(string provider, ClaimsPrincipal providerClaims)
    {
        ArgumentNullException.ThrowIfNull(providerClaims);
        var settings = Settings(provider);

        var nameId = providerClaims.FindFirst(Saml2ClaimTypes.NameId)?.Value;
        if (string.IsNullOrWhiteSpace(nameId) || string.IsNullOrWhiteSpace(settings.IdpEntityId))
        {
            return Error.Failure("provider_error", "The SAML assertion has no subject.");
        }

        var email = settings.EmailAttributes.Select(attribute => providerClaims.FindFirst(attribute)?.Value).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))
            ?? (string.Equals(providerClaims.FindFirst(Saml2ClaimTypes.NameIdFormat)?.Value, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", StringComparison.Ordinal) ? nameId : null);
        var name = settings.NameAttributes.Select(attribute => providerClaims.FindFirst(attribute)?.Value).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
        var context = providerClaims.FindFirst(AuthnContextClaim)?.Value;
        var strength = context is not null && settings.MultiFactorAuthnContexts.Contains(context, StringComparer.Ordinal)
            ? new AuthenticationStrength(["pwd", "mfa"])
            : AuthenticationStrength.Password;

        return new ExternalIdentity(provider, new ExternalLoginKey(settings.LoginIssuer ?? settings.IdpEntityId, nameId), email, settings.EmailVerified && email is not null, name, strength);
    }

    /// <summary>The ITfoxtec configuration of a provider, with this server as the relying party.</summary>
    /// <remarks>
    /// Replays are refused by the assertion consumer, asynchronously, in the shared replay store (ITfoxtec's own hook is
    /// synchronous and would block a thread on the database).
    /// </remarks>
    public Saml2Configuration Configuration(string provider, string serviceProviderEntityId)
    {
        var settings = Settings(provider);
        var configuration = new Saml2Configuration
        {
            Issuer = serviceProviderEntityId,
            SingleSignOnDestination = settings.IdpSingleSignOnUrl ?? metadata.For(provider, settings)?.SingleSignOnUrl,
            AllowedIssuer = settings.IdpEntityId,
            CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None,
            RevocationMode = X509RevocationMode.NoCheck,
            AudienceRestricted = true,
            DetectReplayedTokens = false,
        };
        configuration.AllowedAudienceUris.Add(serviceProviderEntityId);
        configuration.SingleLogoutDestination = SingleLogoutUrl(provider);
        if (SigningCertificate(provider) is { } signing)
        {
            configuration.SigningCertificate = signing;
            configuration.SignAuthnRequest = true;
        }

        if (DecryptionCertificate(provider) is { } decryption)
        {
            configuration.DecryptionCertificates.Add(decryption);
        }

        foreach (var certificate in settings.IdpSigningCertificates)
        {
            configuration.SignatureValidationCertificates.Add(Load(certificate));
        }

        // Certificates from the provider's metadata, so a rollover there needs no change here.
        foreach (var certificate in metadata.For(provider, settings)?.SigningCertificates ?? [])
        {
            configuration.SignatureValidationCertificates.Add(certificate);
        }

        return configuration;
    }

    /// <summary>The provider's single logout URL: configured, or from its metadata; null when it has none.</summary>
    public Uri? SingleLogoutUrl(string provider)
    {
        var settings = Settings(provider);
        return settings.IdpSingleLogoutUrl ?? metadata.For(provider, settings)?.SingleLogoutUrl;
    }

    /// <summary>This server's signing certificate for <paramref name="provider"/>, or null when requests go unsigned.</summary>
    public X509Certificate2? SigningCertificate(string provider)
    {
        // Loaded once per provider: the options instance is cached by the options monitor.
        var settings = Settings(provider);
        return settings.SigningCertificate ??= LoadPfx(settings.SigningCertificatePfx, settings.SigningCertificatePassword);
    }

    /// <summary>This server's decryption certificate for <paramref name="provider"/>, or null when assertions aren't encrypted.</summary>
    public X509Certificate2? DecryptionCertificate(string provider)
    {
        var settings = Settings(provider);
        return settings.DecryptionCertificate ??= LoadPfx(settings.DecryptionCertificatePfx, settings.DecryptionCertificatePassword);
    }

    private static X509Certificate2? LoadPfx(string? pfx, string? password) =>
        string.IsNullOrWhiteSpace(pfx) ? null : X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(pfx), password, X509KeyStorageFlags.EphemeralKeySet);

    public string ServiceProviderEntityId(string provider, IOptions<TokenServerOptions> tokenServer, Uri requestOrigin) =>
        Settings(provider).ServiceProviderEntityId
        ?? new Uri(tokenServer.Value.Issuer ?? requestOrigin, $"{SamlEndpoints.Prefix}/{provider}").AbsoluteUri;

    private static X509Certificate2 Load(string encoded)
    {
        var trimmed = encoded.Trim();
        return trimmed.StartsWith("-----BEGIN", StringComparison.Ordinal)
            ? X509Certificate2.CreateFromPem(trimmed)
            : X509CertificateLoader.LoadCertificate(Convert.FromBase64String(trimmed));
    }
}


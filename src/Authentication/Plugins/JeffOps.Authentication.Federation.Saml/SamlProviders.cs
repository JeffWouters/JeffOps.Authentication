using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Claims;
using JeffOps.Authentication.Abstractions.Replay;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

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
    /// provider a tenant registered is read from its directory (at most a minute old), with its metadata. False when there is
    /// no such provider, or its tenant may no longer use it.
    /// </summary>
    public async Task<bool> PrepareAsync(string provider, CancellationToken cancellationToken)
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

        await metadataClient.EnsureAsync(provider, settings, cancellationToken).ConfigureAwait(false);
        _tenants[provider] = (settings, time.GetUtcNow());
        return true;
    }

    /// <summary>The settings of a provider (after <see cref="PrepareAsync"/> for one a tenant registered).</summary>
    public SamlProviderOptions Settings(string provider) =>
        IsTenantName(provider)
            ? _tenants.TryGetValue(provider, out var cached) ? cached.Settings : new SamlProviderOptions()
            : options.Get(provider);

    private bool IsConfigured(string provider) => registrations.Any(registration => string.Equals(registration.Name, provider, StringComparison.Ordinal));

    private static bool IsTenantName(string provider) => TenantProviderNames.IsTenantProvider(provider);

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
    public Saml2Configuration Configuration(string provider, string serviceProviderEntityId, ITokenReplayCache replayCache)
    {
        var settings = Settings(provider);
        var configuration = new Saml2Configuration
        {
            Issuer = serviceProviderEntityId,
            SingleSignOnDestination = settings.IdpSingleSignOnUrl ?? metadata.For(provider)?.SingleSignOnUrl,
            AllowedIssuer = settings.IdpEntityId,
            CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None,
            RevocationMode = X509RevocationMode.NoCheck,
            AudienceRestricted = true,
            DetectReplayedTokens = true,
            TokenReplayCache = replayCache,
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
        foreach (var certificate in metadata.For(provider)?.SigningCertificates ?? [])
        {
            configuration.SignatureValidationCertificates.Add(certificate);
        }

        return configuration;
    }

    /// <summary>The provider's single logout URL: configured, or from its metadata; null when it has none.</summary>
    public Uri? SingleLogoutUrl(string provider) => Settings(provider).IdpSingleLogoutUrl ?? metadata.For(provider)?.SingleLogoutUrl;

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

/// <summary>
/// Remembers seen assertions until they expire, so a captured SAML response can't be posted twice — in the token server's
/// shared <see cref="IReplayCache"/>, so across every instance.
/// </summary>
/// <remarks>The token handler's replay hook is synchronous; the store's call completes on the calling thread.</remarks>
internal sealed class SamlReplayCache(IReplayCache cache) : ITokenReplayCache
{
    public bool TryAdd(string securityToken, DateTime expiresOn) =>
        cache.TryAddAsync(ReplayKeys.For("saml", securityToken), new DateTimeOffset(DateTime.SpecifyKind(expiresOn, DateTimeKind.Utc)), CancellationToken.None)
            .AsTask().GetAwaiter().GetResult();

    /// <summary>Always false: <see cref="TryAdd"/> is atomic and refuses a replay itself.</summary>
    public bool TryFind(string securityToken) => false;
}

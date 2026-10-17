using System.Security.Claims;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Application.Federation;

/// <summary>
/// A user as an external identity provider reports them, in provider-neutral terms (docs/DESIGN.md §8.1). Provider plug-ins
/// produce it from the provider's own claims; nothing downstream reads provider-specific claims.
/// </summary>
/// <param name="Provider">The configured provider name, e.g. <c>entra</c> or <c>google</c>.</param>
/// <param name="Login">The immutable (issuer, subject) the account is linked by.</param>
/// <param name="Email">The email address, if the provider reports one.</param>
/// <param name="EmailVerified">Whether the provider vouches for the email address.</param>
/// <param name="DisplayName">The display name, if any.</param>
/// <param name="Strength">How strongly the user authenticated at the provider.</param>
public sealed record ExternalIdentity(
    string Provider,
    ExternalLoginKey Login,
    string? Email,
    bool EmailVerified,
    string? DisplayName,
    AuthenticationStrength Strength)
{
    /// <summary>The provider's directory or tenant id (Entra <c>tid</c>), for hosts that map directories to tenants.</summary>
    public string? DirectoryId { get; init; }
}

/// <summary>An external provider as the login page lists it.</summary>
public sealed record ExternalProviderInfo(string Name, string DisplayName);

/// <summary>
/// Turns the claims a provider returned into an <see cref="ExternalIdentity"/>. Each provider plug-in registers one.
/// </summary>
public interface IExternalIdentityMapper
{
    /// <summary>The providers this mapper handles.</summary>
    IReadOnlyCollection<ExternalProviderInfo> Providers { get; }

    /// <summary>The identity for <paramref name="provider"/>, or a failure when the provider's response lacks what is needed.</summary>
    Result<ExternalIdentity> Map(string provider, ClaimsPrincipal providerClaims);
}

/// <summary>
/// Starts a sign-in at a provider that is not an OpenID Connect provider of the OpenIddict client, for example SAML. The
/// federation endpoints send <c>signin/{provider}</c> to <see cref="ChallengePath"/> when a challenge handles the provider.
/// </summary>
public interface IExternalProviderChallenge
{
    bool Handles(string provider);

    /// <summary>The local path that starts the sign-in; it must come back to <paramref name="returnUrl"/> (already local).</summary>
    string ChallengePath(string provider, string returnUrl, string? loginHint);
}

/// <summary>A SAML identity provider a tenant registered for its own people (docs/DESIGN.md §8.4).</summary>
/// <param name="Name">Its name in sign-in URLs (<c>tenant-{id}</c>).</param>
/// <param name="TenantId">The tenant it signs people in for: only addresses in that tenant's verified domains.</param>
/// <param name="DisplayName">What the tenant calls it.</param>
/// <param name="IdpEntityId">The provider's SAML entity id.</param>
/// <param name="MetadataUrl">Its metadata (HTTPS), when it is configured that way.</param>
/// <param name="SingleSignOnUrl">Its sign-in URL (HTTP-Redirect), unless the metadata gives it.</param>
/// <param name="SingleLogoutUrl">Its logout URL, if any.</param>
/// <param name="SigningCertificates">Its signing certificates (base64 DER or PEM), besides the metadata's.</param>
/// <param name="MultiFactorAuthnContexts">Authentication context classes that count as multi-factor.</param>
public sealed record TenantSamlProvider(
    string Name,
    Guid TenantId,
    string DisplayName,
    string IdpEntityId,
    Uri? MetadataUrl,
    Uri? SingleSignOnUrl,
    Uri? SingleLogoutUrl,
    IReadOnlyList<string> SigningCertificates,
    IReadOnlyList<string> MultiFactorAuthnContexts);

/// <summary>Identity providers tenants registered themselves. The Enterprise module provides one; the default knows none.</summary>
public interface ITenantProviderDirectory
{
    /// <summary>The tenant SAML provider named <paramref name="name"/>, or null (unknown, or its tenant may no longer use it).</summary>
    Task<TenantSamlProvider?> FindSamlAsync(string name, CancellationToken cancellationToken);

    /// <summary>The tenant OpenID Connect provider named <paramref name="name"/>, or null (unknown, or its tenant may no longer use it).</summary>
    Task<TenantOidcProvider?> FindOidcAsync(string name, CancellationToken cancellationToken);
}

/// <summary>An OpenID Connect provider a tenant registered for its own people (docs/DESIGN.md §8.4).</summary>
/// <param name="Name">Its name in sign-in URLs (<c>tenant-oidc-{id}</c>).</param>
/// <param name="TenantId">The tenant it signs people in for: only addresses in that tenant's verified domains.</param>
/// <param name="DisplayName">What the tenant calls it.</param>
/// <param name="Issuer">The provider's issuer (HTTPS); its discovery document is read from there.</param>
/// <param name="ClientId">This server's client id at the provider.</param>
/// <param name="ClientSecret">This server's client secret at the provider, if it issued one (decrypted).</param>
/// <param name="Scopes">Scopes to request besides <c>openid</c>.</param>
/// <param name="MultiFactorAcrValues">Authentication context (<c>acr</c>) values that count as multi-factor.</param>
public sealed record TenantOidcProvider(
    string Name,
    Guid TenantId,
    string DisplayName,
    Uri Issuer,
    string ClientId,
    string? ClientSecret,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> MultiFactorAcrValues)
{
    /// <summary>Leaves the client secret out, so it never reaches a log.</summary>
    public override string ToString() => $"TenantOidcProvider {{ Name = {Name}, TenantId = {TenantId}, Issuer = {Issuer}, ClientId = {ClientId} }}";
}

/// <summary>
/// Names of providers tenants registered: <c>tenant-{32 hex}</c> (SAML) and <c>tenant-oidc-{32 hex}</c> (OpenID Connect).
/// They never appear on the login page; only home realm discovery of the tenant's verified domains sends people to them.
/// </summary>
public static class TenantProviderNames
{
    public const string Prefix = "tenant-";

    public const string OidcPrefix = "tenant-oidc-";

    public static bool IsTenantProvider(string? provider) => IsSaml(provider) || IsOidc(provider);

    public static bool IsSaml(string? provider) => IdOf(provider, Prefix) is not null;

    public static bool IsOidc(string? provider) => IdOf(provider, OidcPrefix) is not null;

    private static Guid? IdOf(string? provider, string prefix) =>
        provider is not null && provider.StartsWith(prefix, StringComparison.Ordinal) && Guid.TryParseExact(provider[prefix.Length..], "N", out var id) ? id : null;
}

public sealed class NoTenantProviders : ITenantProviderDirectory
{
    public Task<TenantSamlProvider?> FindSamlAsync(string name, CancellationToken cancellationToken) => Task.FromResult<TenantSamlProvider?>(null);

    public Task<TenantOidcProvider?> FindOidcAsync(string name, CancellationToken cancellationToken) => Task.FromResult<TenantOidcProvider?>(null);
}

/// <summary>
/// Single logout towards the provider a sign-in came from: when the user signs out at the token server, the browser is sent
/// to the provider to sign out there too, and comes back to finish signing out here.
/// </summary>
public interface IExternalSignOut
{
    /// <summary>
    /// Where to send the browser so the provider of <paramref name="signIn"/> signs the user out, coming back to
    /// <paramref name="returnUrl"/> (a local path); null when the sign-in didn't come from such a provider.
    /// </summary>
    Task<string?> SignOutUrlAsync(System.Security.Claims.ClaimsPrincipal signIn, Uri requestOrigin, string returnUrl, CancellationToken cancellationToken);
}

/// <summary>
/// Lets a host react to external sign-ins, for example to create a tenant for a new directory the first time one of its users
/// signs in. Optional; called after the account is created or linked and before the session starts.
/// </summary>
public interface IExternalSignInObserver
{
    Task OnSignedInAsync(Guid accountId, ExternalIdentity identity, bool isNewAccount, CancellationToken cancellationToken);
}

/// <summary>Federation settings. Bound from <see cref="SectionName"/>.</summary>
public sealed class FederationOptions
{
    public const string SectionName = "JeffOps:TokenServer:Federation";

    /// <summary>Create an account on a first external sign-in. When off, only existing (linked) accounts can sign in.</summary>
    public bool AutoProvisionAccounts { get; set; } = true;

    /// <summary>
    /// Email domains allowed to sign in through external providers, e.g. <c>contoso.com</c>. Empty: see
    /// <see cref="OpenRegistration"/>.
    /// </summary>
    public IList<string> AllowedEmailDomains { get; } = [];

    /// <summary>
    /// With no allowed domains, whether anyone may sign in. Off by default outside Development, so a public deployment doesn't
    /// accidentally let every Microsoft or Google account in.
    /// </summary>
    public bool? OpenRegistration { get; set; }

    /// <summary>Home realm discovery: email domain → provider name, e.g. <c>contoso.com</c> → <c>entra</c>.</summary>
    public IDictionary<string, string> DomainProviders { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <summary>The provider for emails whose domain has no mapping; null shows the provider list instead.</summary>
    public string? DefaultProvider { get; set; }

    /// <summary>Authentication context class references (Entra <c>acrs</c>) that count as multi-factor.</summary>
    public IList<string> MultiFactorAuthenticationContexts { get; } = [];
}

/// <summary>
/// What a tenant decided for an email domain it verified (docs/DESIGN.md §8.4): which provider its members sign in with, and
/// whether that is the only way in.
/// </summary>
/// <param name="TenantId">The tenant that verified the domain.</param>
/// <param name="Provider">The provider its members use; null when the tenant has none configured.</param>
/// <param name="SsoOnly">Whether every other sign-in method (passwords, passkeys, other providers) is refused for the domain.</param>
public sealed record RealmPolicy(Guid TenantId, string? Provider, bool SsoOnly);

/// <summary>
/// The accounts a tenant's provisioning (SCIM) created or linked. On the first sign-in through the tenant's own SSO provider,
/// such an account is claimed instead of a second one being created. The Enterprise module provides one; the default knows none.
/// </summary>
public interface IProvisionedAccountDirectory
{
    /// <summary>The account the tenant provisioned for <paramref name="email"/>, or null.</summary>
    Task<Guid?> FindAsync(Guid tenantId, string email, CancellationToken cancellationToken);
}

public sealed class NoProvisionedAccounts : IProvisionedAccountDirectory
{
    public Task<Guid?> FindAsync(Guid tenantId, string email, CancellationToken cancellationToken) => Task.FromResult<Guid?>(null);
}

/// <summary>Tenants' verified email domains and their sign-in policy. The Enterprise module provides one; the default knows none.</summary>
public interface IHomeRealmDirectory
{
    Task<RealmPolicy?> FindByDomainAsync(string domain, CancellationToken cancellationToken);
}

public sealed class NoHomeRealms : IHomeRealmDirectory
{
    public Task<RealmPolicy?> FindByDomainAsync(string domain, CancellationToken cancellationToken) => Task.FromResult<RealmPolicy?>(null);
}

/// <summary>Home realm discovery: which provider an email address signs in with (docs/DESIGN.md §8.4).</summary>
public static class HomeRealm
{
    /// <summary>
    /// The provider for a sign-in, in order: an explicit <paramref name="idpHint"/>, the host's domain mapping, the tenant's
    /// verified domain, the default provider. Null when the user must choose (or use a local method). A provider a tenant
    /// registered itself is reached only through the tenant's verified domain, never by hint or default.
    /// </summary>
    public static async Task<string?> DiscoverAsync(
        string? email, string? idpHint, FederationOptions options, IReadOnlyCollection<string> knownProviders, IHomeRealmDirectory realms, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(knownProviders);
        ArgumentNullException.ThrowIfNull(realms);

        bool Known(string? provider) => provider is not null && knownProviders.Contains(provider, StringComparer.OrdinalIgnoreCase);

        if (Known(idpHint))
        {
            return idpHint;
        }

        var domain = DomainOf(email);
        if (domain is not null && options.DomainProviders.TryGetValue(domain, out var mapped) && Known(mapped))
        {
            return mapped;
        }

        if (domain is not null && await realms.FindByDomainAsync(domain, cancellationToken).ConfigureAwait(false) is { Provider: { } tenantProvider }
            && (Known(tenantProvider) || TenantProviderNames.IsTenantProvider(tenantProvider)))
        {
            return tenantProvider;
        }

        return Known(options.DefaultProvider) ? options.DefaultProvider : null;
    }

    public static string? DomainOf(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return null;
        }

        var at = email.LastIndexOf('@');
        return at > 0 && at < email.Length - 1 ? email[(at + 1)..].Trim().ToLowerInvariant() : null;
    }
}

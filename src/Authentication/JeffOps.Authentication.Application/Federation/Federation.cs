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

/// <summary>Home realm discovery: which provider an email address signs in with (docs/DESIGN.md §8.4).</summary>
public static class HomeRealm
{
    /// <summary>The provider for <paramref name="email"/>, or null when the user must choose.</summary>
    public static string? Discover(string? email, FederationOptions options, IReadOnlyCollection<string> knownProviders)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(knownProviders);

        var domain = DomainOf(email);
        var provider = domain is not null && options.DomainProviders.TryGetValue(domain, out var mapped) ? mapped : options.DefaultProvider;
        return provider is not null && knownProviders.Contains(provider, StringComparer.OrdinalIgnoreCase) ? provider : null;
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

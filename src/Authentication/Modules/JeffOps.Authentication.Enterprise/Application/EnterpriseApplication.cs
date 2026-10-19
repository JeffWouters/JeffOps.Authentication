using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Enterprise.Domain;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Enterprise.Application;

/// <summary>Enterprise features (docs/DESIGN.md §8.4). Bound from <see cref="SectionName"/>.</summary>
public sealed class EnterpriseOptions
{
    public const string SectionName = "JeffOps:Enterprise";

    /// <summary>The DNS label the verification TXT record goes under: <c>{label}.{domain}</c>. Default: <c>_jeffops-challenge</c>.</summary>
    public string ChallengeLabel { get; set; } = "_jeffops-challenge";

    /// <summary>The TXT value prefix; the value is <c>{prefix}{token}</c>. Default: <c>jeffops-verification=</c>.</summary>
    public string ChallengeValuePrefix { get; set; } = "jeffops-verification=";

    /// <summary>The DNS-over-HTTPS JSON endpoint used to read TXT records. Default: Cloudflare.</summary>
    public Uri DnsOverHttpsEndpoint { get; set; } = new("https://cloudflare-dns.com/dns-query");

    /// <summary>The authorization policy a tenant administrator needs. Default: <c>auth.enterprise.manage</c>.</summary>
    public string ManagePolicy { get; set; } = "auth.enterprise.manage";

    public int MaxDomainsPerTenant { get; set; } = 20;

    /// <summary>Whether this host re-checks verified domains' DNS proof in the background (one host is enough). Default: true.</summary>
    public bool RecheckDomains { get; set; } = true;

    /// <summary>How often each verified domain's DNS proof is checked again. Default: daily.</summary>
    public TimeSpan DomainRecheckInterval { get; set; } = TimeSpan.FromDays(1);

    /// <summary>
    /// How long a verified domain's DNS proof may be missing before the domain drops back to pending (the tenant then has to
    /// verify it again, and its users' sign-ins stop depending on it). Default: 7 days.
    /// </summary>
    public TimeSpan DomainProofGracePeriod { get; set; } = TimeSpan.FromDays(7);

    /// <summary>How many of its own identity providers a tenant may register. Default: 5.</summary>
    public int MaxProvidersPerTenant { get; set; } = 5;

    /// <summary>
    /// The authorization policy platform operators need to allow a tenant its own identity providers. Default:
    /// <c>auth.enterprise.operate</c>.
    /// </summary>
    public string OperatorPolicy { get; set; } = "auth.enterprise.operate";

    /// <summary>
    /// The policy needed, on top of <see cref="ManagePolicy"/>, to create SCIM tokens. A SCIM token controls group membership,
    /// and groups can hold roles, so whoever holds one can put people (themselves included) into role-bearing groups: require
    /// at least the right to assign the roles groups hold. A host that doesn't define this policy can't create SCIM tokens
    /// (fail closed). Set it to null to allow every tenant administrator. Default: <c>auth.enterprise.scim_tokens</c>.
    /// </summary>
    public string? ScimTokenPolicy { get; set; } = "auth.enterprise.scim_tokens";
}

public interface ITenantDomainRepository
{
    Task<TenantDomain?> FindAsync(Guid domainId, CancellationToken cancellationToken);

    Task<IReadOnlyList<TenantDomain>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken);

    Task<TenantDomain?> FindVerifiedAsync(string domain, CancellationToken cancellationToken);

    /// <summary>Verified domains last checked before <paramref name="checkedBefore"/>, oldest check first.</summary>
    Task<IReadOnlyList<TenantDomain>> ListVerifiedCheckedBeforeAsync(DateTimeOffset checkedBefore, int take, CancellationToken cancellationToken);

    void Add(TenantDomain domain);

    void Remove(TenantDomain domain);
}

public interface ITenantIdentityProviderRepository
{
    Task<TenantIdentityProvider?> FindAsync(Guid providerId, CancellationToken cancellationToken);

    Task<IReadOnlyList<TenantIdentityProvider>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken);

    void Add(TenantIdentityProvider provider);

    void Remove(TenantIdentityProvider provider);
}

public interface ITenantOidcProviderRepository
{
    Task<TenantOidcIdentityProvider?> FindAsync(Guid providerId, CancellationToken cancellationToken);

    Task<IReadOnlyList<TenantOidcIdentityProvider>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken);

    void Add(TenantOidcIdentityProvider provider);

    void Remove(TenantOidcIdentityProvider provider);
}

/// <summary>Encrypts the client secrets of tenants' OIDC providers at rest. The default uses Data Protection.</summary>
public interface IClientSecretProtector
{
    string Protect(string secret);

    /// <summary>The secret, or null when it can't be decrypted (for example, its key was removed from the key ring).</summary>
    string? Unprotect(string protectedSecret);
}

public interface ISsoPolicyRepository
{
    Task<SsoPolicy?> FindAsync(Guid tenantId, CancellationToken cancellationToken);

    void Add(SsoPolicy policy);
}

public interface IEnterpriseUnitOfWork
{
    Task SaveChangesAsync(CancellationToken cancellationToken);

    /// <summary>Saves, or answers false (saving nothing) when another request changed a versioned resource meanwhile.</summary>
    Task<bool> TrySaveChangesAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Saves, or answers false (saving nothing) when the store refuses the change, for example a uniqueness constraint another
    /// request satisfied first.
    /// </summary>
    Task<bool> TrySaveUniqueAsync(CancellationToken cancellationToken);
}

/// <summary>Reads TXT records. The default uses DNS over HTTPS.</summary>
public interface IDnsTxtResolver
{
    /// <summary>The TXT strings at <paramref name="name"/>; empty when there are none. Throws when DNS can't be reached.</summary>
    Task<IReadOnlyList<string>> ResolveTxtAsync(string name, CancellationToken cancellationToken);
}

/// <summary>A tenant administrator acting on their own tenant (read from their token by the endpoint).</summary>
public sealed record EnterpriseCaller(Guid UserId, Guid TenantId);

public static class EnterpriseErrors
{
    public const string InvalidDomain = "invalid_domain";
    public const string DomainTaken = "domain_taken";
    public const string TooManyDomains = "too_many_domains";
    public const string NotFound = "not_found";
    public const string NotVerified = "not_verified";
    public const string DnsUnavailable = "dns_unavailable";
    public const string UnknownProvider = "unknown_provider";
    public const string NoVerifiedDomain = "no_verified_domain";
    public const string CustomProvidersNotAllowed = "custom_providers_not_allowed";
    public const string TooManyProviders = "too_many_providers";
}

/// <summary>Tenants' own providers, for the SAML and OIDC plugins; only while an operator allows the tenant to have them.</summary>
public sealed class EnterpriseTenantProviders(
    ITenantIdentityProviderRepository providers,
    ITenantOidcProviderRepository oidcProviders,
    ISsoPolicyRepository policies,
    IClientSecretProtector secrets) : ITenantProviderDirectory
{
    public async Task<TenantOidcProvider?> FindOidcAsync(string name, CancellationToken cancellationToken)
    {
        if (TenantOidcIdentityProvider.IdOf(name) is not { } id
            || await oidcProviders.FindAsync(id, cancellationToken).ConfigureAwait(false) is not { } provider
            || await policies.FindAsync(provider.TenantId, cancellationToken).ConfigureAwait(false) is not { CustomProvidersAllowed: true })
        {
            return null;
        }

        string? secret = null;
        if (provider.ProtectedClientSecret is { } protectedSecret && (secret = secrets.Unprotect(protectedSecret)) is null)
        {
            // A secret that can't be decrypted can't sign anyone in; the administrator has to enter it again.
            return null;
        }

        return new TenantOidcProvider(
            provider.Name,
            provider.TenantId,
            provider.DisplayName,
            new Uri(provider.Issuer),
            provider.ClientId,
            secret,
            provider.ScopeList,
            provider.MultiFactorAcrValueList);
    }

    public async Task<TenantSamlProvider?> FindSamlAsync(string name, CancellationToken cancellationToken)
    {
        if (TenantIdentityProvider.IdOf(name) is not { } id
            || await providers.FindAsync(id, cancellationToken).ConfigureAwait(false) is not { } provider
            || await policies.FindAsync(provider.TenantId, cancellationToken).ConfigureAwait(false) is not { CustomProvidersAllowed: true })
        {
            return null;
        }

        return new TenantSamlProvider(
            provider.Name,
            provider.TenantId,
            provider.DisplayName,
            provider.EntityId,
            Url(provider.MetadataUrl),
            Url(provider.SingleSignOnUrl),
            Url(provider.SingleLogoutUrl),
            provider.CertificateList,
            provider.MultiFactorAuthnContextList);
    }

    private static Uri? Url(string? value) => value is null ? null : new Uri(value);
}

/// <summary>The accounts a tenant's SCIM provisioning created or linked, by email.</summary>
public sealed class ScimProvisionedAccounts(IAccountRepository accounts, IScimUserRepository users) : IProvisionedAccountDirectory
{
    public async Task<ProvisionedAccount?> FindAsync(Guid tenantId, string email, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        return await accounts.FindByEmailAsync(email, cancellationToken).ConfigureAwait(false) is { } account
            && await users.FindAsync(tenantId, account.Id, cancellationToken).ConfigureAwait(false) is { } user
            ? new ProvisionedAccount(account.Id, user.CreatedAccount)
            : null;
    }
}

/// <summary>Home realm discovery and SSO policy from tenants' verified domains.</summary>
public sealed class EnterpriseHomeRealms(ITenantDomainRepository domains, ISsoPolicyRepository policies) : IHomeRealmDirectory
{
    public async Task<RealmPolicy?> FindByDomainAsync(string domain, CancellationToken cancellationToken)
    {
        if (TenantDomain.Normalize(domain) is not { } normalized
            || await domains.FindVerifiedAsync(normalized, cancellationToken).ConfigureAwait(false) is not { } verified)
        {
            return null;
        }

        var policy = await policies.FindAsync(verified.TenantId, cancellationToken).ConfigureAwait(false);
        return new RealmPolicy(verified.TenantId, policy?.Provider, policy?.SsoOnly ?? false);
    }
}

internal static class OptionsExtensions
{
    public static string ChallengeName(this IOptions<EnterpriseOptions> options, TenantDomain domain) => $"{options.Value.ChallengeLabel}.{domain.Domain}";
}

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
}

public interface ITenantDomainRepository
{
    Task<TenantDomain?> FindAsync(Guid domainId, CancellationToken cancellationToken);

    Task<IReadOnlyList<TenantDomain>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken);

    Task<TenantDomain?> FindVerifiedAsync(string domain, CancellationToken cancellationToken);

    void Add(TenantDomain domain);

    void Remove(TenantDomain domain);
}

public interface ISsoPolicyRepository
{
    Task<SsoPolicy?> FindAsync(Guid tenantId, CancellationToken cancellationToken);

    void Add(SsoPolicy policy);
}

public interface IEnterpriseUnitOfWork
{
    Task SaveChangesAsync(CancellationToken cancellationToken);
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

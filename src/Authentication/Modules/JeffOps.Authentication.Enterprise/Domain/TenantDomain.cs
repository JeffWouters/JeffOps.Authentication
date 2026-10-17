using System.Globalization;
using System.Security.Cryptography;
using JeffOps.Authentication.SharedKernel.Domain;

namespace JeffOps.Authentication.Enterprise.Domain;

public enum DomainStatus
{
    Pending = 0,
    Verified = 1,
}

/// <summary>
/// An email domain a tenant claims. It only counts — for home realm discovery and single sign-on policy — once the tenant
/// proved control by publishing the verification token in DNS. A domain can be verified by one tenant at a time.
/// </summary>
public sealed class TenantDomain : AggregateRoot<Guid>
{
    private TenantDomain(Guid tenantId, string domain, DateTimeOffset now)
        : base(Guid.NewGuid())
    {
        TenantId = tenantId;
        Domain = domain;
        VerificationToken = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        Status = DomainStatus.Pending;
        CreatedAt = now;
    }

    private TenantDomain()
    {
    }

    public Guid TenantId { get; private set; }

    /// <summary>Lower-case ASCII (IDN-encoded) host name, for example <c>contoso.com</c>.</summary>
    public string Domain { get; private set; } = string.Empty;

    public string VerificationToken { get; private set; } = string.Empty;

    public DomainStatus Status { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? VerifiedAt { get; private set; }

    public DateTimeOffset? LastCheckedAt { get; private set; }

    public static TenantDomain Claim(Guid tenantId, string domain, DateTimeOffset now) =>
        Normalize(domain) is { } normalized
            ? new TenantDomain(tenantId, normalized, now)
            : throw new ArgumentException("Not a valid domain name.", nameof(domain));

    /// <summary>The TXT value that proves control: <c>{prefix}{token}</c>.</summary>
    public string ExpectedValue(string prefix) => prefix + VerificationToken;

    /// <summary>Checks the TXT values found in DNS; verifies the domain when one matches.</summary>
    public bool CheckTxtRecords(IEnumerable<string> values, string prefix, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(values);
        LastCheckedAt = now;
        if (Status == DomainStatus.Verified)
        {
            return true;
        }

        var expected = ExpectedValue(prefix);
        if (!values.Any(value => string.Equals(value.Trim().Trim('"'), expected, StringComparison.Ordinal)))
        {
            return false;
        }

        Status = DomainStatus.Verified;
        VerifiedAt = now;
        Raise(new TenantDomainVerified(TenantId, Domain));
        return true;
    }

    /// <summary>
    /// The domain in canonical form, or null when it is not a plausible registrable host name (at least two labels, letters,
    /// digits and hyphens; internationalized names are IDN-encoded).
    /// </summary>
    public static string? Normalize(string? domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return null;
        }

        string ascii;
        try
        {
            ascii = new IdnMapping().GetAscii(domain.Trim().TrimEnd('.').TrimStart('@')).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return null;
        }

        var labels = ascii.Split('.');
        var valid = ascii.Length <= 253
            && labels.Length >= 2
            && labels.All(label => label.Length is > 0 and <= 63
                && label.All(character => char.IsAsciiLetterOrDigit(character) || character == '-')
                && !label.StartsWith('-') && !label.EndsWith('-'))
            && !labels[^1].All(char.IsAsciiDigit);
        return valid ? ascii : null;
    }
}

public sealed record TenantDomainVerified(Guid TenantId, string Domain) : IDomainEvent;

/// <summary>
/// A tenant's single sign-on policy: which configured identity provider its members (by verified email domain) sign in with,
/// and whether that's the only way in.
/// </summary>
public sealed class SsoPolicy
{
    private SsoPolicy(Guid tenantId)
    {
        TenantId = tenantId;
    }

    private SsoPolicy()
    {
    }

    public Guid TenantId { get; private set; }

    public string? Provider { get; private set; }

    public bool SsoOnly { get; private set; }

    /// <summary>Whether a platform operator allowed this tenant to register its own identity providers.</summary>
    public bool CustomProvidersAllowed { get; private set; }

    public DateTimeOffset UpdatedAt { get; private set; }

    public Guid? UpdatedBy { get; private set; }

    public static SsoPolicy For(Guid tenantId) => new(tenantId);

    /// <summary>
    /// Allows or stops the tenant's own identity providers (an operator's decision). Stopping them also drops them from the SSO
    /// policy, since they no longer sign anyone in.
    /// </summary>
    public void AllowCustomProviders(bool allowed, Guid by, DateTimeOffset now)
    {
        CustomProvidersAllowed = allowed;
        if (!allowed && Provider?.StartsWith(TenantIdentityProvider.NamePrefix, StringComparison.Ordinal) == true)
        {
            Provider = null;
            SsoOnly = false;
        }

        UpdatedBy = by;
        UpdatedAt = now;
    }

    /// <summary>Sets the policy. SSO-only needs a provider, or nobody of the tenant's domains could sign in.</summary>
    public void Set(string? provider, bool ssoOnly, Guid? by, DateTimeOffset now)
    {
        if (ssoOnly && string.IsNullOrWhiteSpace(provider))
        {
            throw new ArgumentException("SSO-only needs a provider.", nameof(ssoOnly));
        }

        Provider = string.IsNullOrWhiteSpace(provider) ? null : provider.Trim();
        SsoOnly = ssoOnly;
        UpdatedBy = by;
        UpdatedAt = now;
    }
}

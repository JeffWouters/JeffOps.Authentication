namespace JeffOps.Authentication.Domain.Accounts;

/// <summary>
/// The immutable identity of an account at an external provider: the provider's issuer and the subject it assigns. This,
/// never an email address, is what links a sign-in to an account (docs/DESIGN.md §8.2), so a provider letting a user change
/// their email can't be used to take over someone else's account.
/// </summary>
public sealed record ExternalLoginKey
{
    public ExternalLoginKey(string issuer, string subject)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        // Issuers are URLs (case-insensitive host) and subjects are opaque; providers differ in casing, so both are normalized
        // the same way the origin normalized Entra (tid, oid). A provider with case-sensitive subjects must not reuse a subject
        // that differs only in case, which no known provider does.
        Issuer = issuer.Trim().TrimEnd('/').ToLowerInvariant();
        Subject = subject.Trim().ToLowerInvariant();
    }

    public string Issuer { get; }

    public string Subject { get; }
}

/// <summary>An external login linked to an account.</summary>
public sealed class ExternalLogin
{
    internal ExternalLogin(Guid accountId, ExternalLoginKey key, string provider, DateTimeOffset linkedAt)
    {
        AccountId = accountId;
        Issuer = key.Issuer;
        Subject = key.Subject;
        Provider = provider;
        LinkedAt = linkedAt;
    }

    private ExternalLogin()
    {
    }

    public Guid AccountId { get; private set; }

    public string Issuer { get; private set; } = string.Empty;

    public string Subject { get; private set; } = string.Empty;

    /// <summary>The configured provider name that linked it, for display and diagnostics.</summary>
    public string Provider { get; private set; } = string.Empty;

    public DateTimeOffset LinkedAt { get; private set; }

    public ExternalLoginKey Key => new(Issuer, Subject);
}

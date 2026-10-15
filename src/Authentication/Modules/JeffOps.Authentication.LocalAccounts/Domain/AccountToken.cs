using System.Security.Cryptography;
using System.Text;

namespace JeffOps.Authentication.LocalAccounts.Domain;

public enum AccountTokenPurpose
{
    EmailVerification = 0,
    PasswordReset = 1,
}

/// <summary>
/// A single-use token sent by email (verification, password reset). Only its SHA-256 is stored; the secret exists in the
/// email alone. Issuing a new token of a purpose supersedes the older ones.
/// </summary>
public sealed class AccountToken
{
    private AccountToken(Guid accountId, AccountTokenPurpose purpose, string tokenHash, DateTimeOffset now, TimeSpan lifetime)
    {
        Id = Guid.NewGuid();
        AccountId = accountId;
        Purpose = purpose;
        TokenHash = tokenHash;
        CreatedAt = now;
        ExpiresAt = now + lifetime;
    }

    private AccountToken()
    {
        TokenHash = string.Empty;
    }

    public Guid Id { get; private set; }

    public Guid AccountId { get; private set; }

    public AccountTokenPurpose Purpose { get; private set; }

    public string TokenHash { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset ExpiresAt { get; private set; }

    public DateTimeOffset? UsedAt { get; private set; }

    /// <summary>A new token and its secret (to send; never stored).</summary>
    public static (AccountToken Token, string Secret) Issue(Guid accountId, AccountTokenPurpose purpose, DateTimeOffset now, TimeSpan lifetime)
    {
        var secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (new AccountToken(accountId, purpose, HashOf(secret), now, lifetime), secret);
    }

    public static string HashOf(string secret) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret ?? string.Empty)));

    public bool IsUsableAt(DateTimeOffset now) => UsedAt is null && now < ExpiresAt;

    public bool Use(DateTimeOffset now)
    {
        if (!IsUsableAt(now))
        {
            return false;
        }

        UsedAt = now;
        return true;
    }

    /// <summary>Retires the token without using it (superseded by a newer one).</summary>
    public void Retire(DateTimeOffset now) => UsedAt ??= now;
}

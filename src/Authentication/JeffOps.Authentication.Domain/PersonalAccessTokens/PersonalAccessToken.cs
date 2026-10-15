using System.Security.Cryptography;
using System.Text;
using JeffOps.Authentication.SharedKernel.Domain;

namespace JeffOps.Authentication.Domain.PersonalAccessTokens;

/// <summary>
/// A personal access token: a long-lived API credential created by an account and exchanged for short-lived access tokens.
/// Only a SHA-256 hash of the secret is stored. Every token expires, bounded by the platform's maximum lifetime even if
/// that maximum is lowered after creation. Bound to one tenant and optionally to a permission ceiling.
/// </summary>
public sealed class PersonalAccessToken : AggregateRoot<Guid>
{
    private PersonalAccessToken(
        Guid id,
        Guid accountId,
        string name,
        string secretHash,
        Guid? tenantId,
        IReadOnlyCollection<string> permissionCeiling,
        bool allowSensitiveActions,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt)
        : base(id)
    {
        AccountId = accountId;
        Name = name;
        SecretHash = secretHash;
        TenantId = tenantId;
        PermissionCeiling = string.Join(' ', permissionCeiling);
        AllowSensitiveActions = allowSensitiveActions;
        CreatedAt = createdAt;
        ExpiresAt = expiresAt;
    }

    private PersonalAccessToken()
    {
    }

    public Guid AccountId { get; private set; }

    public string Name { get; private set; } = string.Empty;

    public string SecretHash { get; private set; } = string.Empty;

    public Guid? TenantId { get; private set; }

    /// <summary>Space-separated permission codes; empty means no ceiling (the owner's own permissions).</summary>
    public string PermissionCeiling { get; private set; } = string.Empty;

    /// <summary>Whether tokens minted from this PAT may perform step-up-protected (sensitive) actions.</summary>
    public bool AllowSensitiveActions { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset ExpiresAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; private set; }

    public DateTimeOffset? LastUsedAt { get; private set; }

    public bool IsRevoked => RevokedAt is not null;

    /// <summary>Creates a token and returns it with the one-time plaintext secret, which is never stored.</summary>
    public static (PersonalAccessToken Token, string Secret) Create(
        Guid accountId,
        string name,
        Guid? tenantId,
        IReadOnlyCollection<string> permissionCeiling,
        bool allowSensitiveActions,
        TimeSpan lifetime,
        string secretPrefix,
        DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(permissionCeiling);
        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "A personal access token must expire.");
        }

        var secret = PatSecret.Generate(secretPrefix);
        var token = new PersonalAccessToken(
            Guid.CreateVersion7(now),
            accountId,
            name.Trim(),
            PatSecret.Hash(secret),
            tenantId,
            [.. permissionCeiling.Where(code => !string.IsNullOrWhiteSpace(code)).Select(code => code.Trim())],
            allowSensitiveActions,
            now,
            now + lifetime);
        token.Raise(new PersonalAccessTokenCreated(token.Id, accountId));
        return (token, secret);
    }

    /// <summary>When the token stops working: its own expiry, or creation plus the current maximum lifetime if sooner.</summary>
    public DateTimeOffset EffectiveExpiresAt(TimeSpan maxLifetime) =>
        ExpiresAt < CreatedAt + maxLifetime ? ExpiresAt : CreatedAt + maxLifetime;

    public bool IsActive(DateTimeOffset now, TimeSpan maxLifetime) => !IsRevoked && now < EffectiveExpiresAt(maxLifetime);

    public IReadOnlyList<string> Ceiling() =>
        PermissionCeiling.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public void MarkUsed(DateTimeOffset now) => LastUsedAt = now;

    /// <summary>Revokes the token. Returns false when it already was revoked.</summary>
    public bool Revoke(DateTimeOffset now)
    {
        if (IsRevoked)
        {
            return false;
        }

        RevokedAt = now;
        Raise(new PersonalAccessTokenRevoked(Id, AccountId));
        return true;
    }
}

public sealed record PersonalAccessTokenCreated(Guid TokenId, Guid AccountId) : IDomainEvent;

public sealed record PersonalAccessTokenRevoked(Guid TokenId, Guid AccountId) : IDomainEvent;

/// <summary>Generation and hashing of personal access token secrets.</summary>
public static class PatSecret
{
    private const int SecretBytes = 32;

    /// <summary>A new secret: the prefix (which makes leaked tokens easy to recognise and scan for) and 256 random bits.</summary>
    public static string Generate(string prefix)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(prefix);
        return prefix + Base64UrlEncode(RandomNumberGenerator.GetBytes(SecretBytes));
    }

    /// <summary>The stored form of a secret: lower-case hex SHA-256. A fast hash is right here: the secret has 256 bits of entropy.</summary>
    public static string Hash(string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
    }

    public static bool LooksLikeSecret(string? value, string prefix) =>
        value is not null && value.StartsWith(prefix, StringComparison.Ordinal) && value.Length > prefix.Length + 20;

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

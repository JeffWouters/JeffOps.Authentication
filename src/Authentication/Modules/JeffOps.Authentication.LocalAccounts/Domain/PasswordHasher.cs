using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace JeffOps.Authentication.LocalAccounts.Domain;

/// <summary>The outcome of checking a password against a stored hash.</summary>
/// <param name="Valid">Whether the password matches.</param>
/// <param name="NeedsRehash">Whether the hash uses an older format or fewer iterations than now required; rehash on success.</param>
public readonly record struct PasswordCheck(bool Valid, bool NeedsRehash);

/// <summary>
/// Password hashing (docs/DESIGN.md §8.5, D10). Current format <c>v2</c>: PBKDF2-HMAC-SHA512, 16-byte salt, 32-byte key,
/// iterations recorded in the hash (default 210,000, OWASP 2023). Format <c>v1</c> (PBKDF2-HMAC-SHA256) is accepted for
/// imported accounts and rehashed on the next successful sign-in. Comparisons are constant time.
/// </summary>
public static class PasswordHasher
{
    public const int DefaultIterations = 210_000;
    public const int MinimumIterations = 10_000;

    private const int SaltSize = 16;
    private const int KeySize = 32;

    /// <summary>Hashes <paramref name="password"/> as <c>v2.{iterations}.{salt}.{key}</c> (base64).</summary>
    public static string Hash(string password, int iterations = DefaultIterations)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, MinimumIterations);

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA512, KeySize);
        return string.Create(CultureInfo.InvariantCulture, $"v2.{iterations}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(key)}");
    }

    /// <summary>Checks <paramref name="password"/> against <paramref name="hash"/>. A malformed hash never matches.</summary>
    public static PasswordCheck Verify(string hash, string password, int requiredIterations = DefaultIterations)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (string.IsNullOrEmpty(hash))
        {
            return default;
        }

        var parts = hash.Split('.');
        if (parts.Length != 4
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var iterations)
            || iterations < 1
            || !TryBase64(parts[2], out var salt)
            || !TryBase64(parts[3], out var expected))
        {
            return default;
        }

        var algorithm = parts[0] switch
        {
            "v2" => HashAlgorithmName.SHA512,
            "v1" => HashAlgorithmName.SHA256,
            _ => default,
        };
        if (algorithm == default)
        {
            return default;
        }

        var actual = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, algorithm, expected.Length);
        var valid = CryptographicOperations.FixedTimeEquals(actual, expected);
        return new PasswordCheck(valid, valid && (parts[0] != "v2" || iterations < requiredIterations));
    }

    /// <summary>
    /// Spends the same work as a real check, for sign-ins with unknown emails, so response time doesn't reveal which emails
    /// have accounts.
    /// </summary>
    public static void VerifyNothing(string password, int iterations = DefaultIterations) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password ?? string.Empty), new byte[SaltSize], iterations, HashAlgorithmName.SHA512, KeySize);

    private static bool TryBase64(string value, out byte[] bytes)
    {
        bytes = new byte[value.Length];
        if (Convert.TryFromBase64String(value, bytes, out var written))
        {
            bytes = bytes[..written];
            return written > 0;
        }

        return false;
    }
}

/// <summary>The password rules: length only, as NIST SP 800-63B recommends (no composition rules).</summary>
public static class PasswordRules
{
    public static string? Problem(string? password, int minimumLength)
    {
        if (string.IsNullOrEmpty(password) || password.Length < minimumLength)
        {
            return $"Use at least {minimumLength} characters.";
        }

        return password.Length > 256 ? "Use at most 256 characters." : null;
    }
}

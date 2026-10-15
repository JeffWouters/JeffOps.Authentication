using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace JeffOps.Authentication.LocalAccounts.Domain;

/// <summary>Time-based one-time passwords (RFC 6238): HMAC-SHA1, 30-second steps, 6 digits — what authenticator apps expect.</summary>
public static class Totp
{
    public const int Digits = 6;
    public static readonly TimeSpan Step = TimeSpan.FromSeconds(30);

    /// <summary>A new 160-bit secret.</summary>
    public static byte[] NewSecret() => RandomNumberGenerator.GetBytes(20);

    /// <summary>The time step of <paramref name="at"/>.</summary>
    public static long StepOf(DateTimeOffset at) => at.ToUnixTimeSeconds() / (long)Step.TotalSeconds;

    public static string Code(byte[] secret, long step)
    {
        ArgumentNullException.ThrowIfNull(secret);

        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);
        Span<byte> mac = stackalloc byte[20];
#pragma warning disable CA5350 // RFC 6238 and every authenticator app use HMAC-SHA1; HMAC-SHA1 is not broken.
        HMACSHA1.HashData(secret, counter, mac);
#pragma warning restore CA5350
        var offset = mac[^1] & 0x0F;
        var binary = (BinaryPrimitives.ReadInt32BigEndian(mac[offset..]) & 0x7FFFFFFF) % 1_000_000;
        return binary.ToString("D6", CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// The step <paramref name="code"/> matches within one step of clock drift, or null. Steps at or before
    /// <paramref name="lastUsedStep"/> are refused, so a code can't be replayed.
    /// </summary>
    public static long? Match(byte[] secret, string? code, DateTimeOffset now, long? lastUsedStep)
    {
        ArgumentNullException.ThrowIfNull(secret);
        var normalized = code?.Replace(" ", string.Empty, StringComparison.Ordinal);
        if (normalized is not { Length: Digits } || !normalized.All(char.IsAsciiDigit))
        {
            return null;
        }

        var current = StepOf(now);
        for (var step = current - 1; step <= current + 1; step++)
        {
            if (step > (lastUsedStep ?? long.MinValue)
                && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Code(secret, step)), Encoding.ASCII.GetBytes(normalized)))
            {
                return step;
            }
        }

        return null;
    }

    /// <summary>The <c>otpauth://</c> URI authenticator apps scan.</summary>
    public static string Uri(byte[] secret, string issuer, string account) =>
        $"otpauth://totp/{System.Uri.EscapeDataString(issuer)}:{System.Uri.EscapeDataString(account)}?secret={Base32(secret)}&issuer={System.Uri.EscapeDataString(issuer)}&digits={Digits}&period={(int)Step.TotalSeconds}";

    /// <summary>RFC 4648 base32 without padding, as authenticator apps expect.</summary>
    public static string Base32(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (var value in data)
        {
            buffer = (buffer << 8) | value;
            bits += 8;
            while (bits >= 5)
            {
                output.Append(Alphabet[(buffer >> (bits - 5)) & 31]);
                bits -= 5;
            }
        }

        if (bits > 0)
        {
            output.Append(Alphabet[(buffer << (5 - bits)) & 31]);
        }

        return output.ToString();
    }
}

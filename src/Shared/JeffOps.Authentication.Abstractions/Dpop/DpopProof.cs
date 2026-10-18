using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JeffOps.Authentication.Abstractions.Dpop;

/// <summary>A valid DPoP proof (RFC 9449): the key's thumbprint, and the proof's id and time for replay checks.</summary>
/// <param name="Jkt">The RFC 7638 SHA-256 thumbprint of the proof's public key (what <c>cnf.jkt</c> holds).</param>
/// <param name="Jti">The proof's unique id, for the replay cache.</param>
/// <param name="IssuedAt">When the proof was made.</param>
public sealed record DpopProof(string Jkt, string Jti, DateTimeOffset IssuedAt)
{
    /// <summary>The server-provided nonce the proof carries (RFC 9449 §8), if any.</summary>
    public string? Nonce { get; init; }
}

/// <summary>
/// Validates DPoP proofs (RFC 9449 §4.3) without any token library: a compact JWS whose header carries <c>typ=dpop+jwt</c>, an
/// asymmetric <c>alg</c> and the public <c>jwk</c> it is signed with, and whose claims bind it to one request (<c>htm</c>,
/// <c>htu</c>), one moment (<c>iat</c>) and, at a resource server, one access token (<c>ath</c>). Callers check
/// <see cref="DpopProof.Jti"/> against a replay cache and <see cref="DpopProof.Jkt"/> against the token's <c>cnf.jkt</c>.
/// </summary>
public static class DpopProofValidator
{
    /// <summary>The HTTP request header that carries the DPoP proof.</summary>
    public const string HeaderName = "DPoP";
    /// <summary>The <c>Authorization</c> scheme for a DPoP-bound access token, used in place of <c>Bearer</c>.</summary>
    public const string Scheme = "DPoP";

    /// <summary>The response header carrying a server-provided nonce (RFC 9449 §8).</summary>
    public const string NonceHeaderName = "DPoP-Nonce";

    /// <summary>The signature algorithms accepted (and advertised as <c>dpop_signing_alg_values_supported</c>).</summary>
    public static IReadOnlyList<string> Algorithms { get; } = ["ES256", "ES384", "ES512", "PS256", "RS256"];

    /// <summary>The longest <c>jti</c> accepted; replay caches hold every one for the proof's lifetime.</summary>
    public const int MaxJtiLength = 128;

    /// <summary>
    /// Imported public keys, by RFC 7638 thumbprint (which covers exactly the key material), so a client's key is turned into
    /// a key object once rather than for every proof. Instances aren't shared between concurrent checks: each check rents
    /// one and returns it. Bounded: at most <see cref="MaxCachedKeys"/> keys and <see cref="MaxInstancesPerKey"/> instances each.
    /// </summary>
    private static readonly ConcurrentDictionary<string, ConcurrentBag<AsymmetricAlgorithm>> ImportedKeys = new(StringComparer.Ordinal);
    private const int MaxCachedKeys = 1024;
    private const int MaxInstancesPerKey = 8;

    /// <summary>
    /// Validates <paramref name="proof"/> for a request of <paramref name="method"/> to <paramref name="uri"/> at
    /// <paramref name="now"/>. With <paramref name="accessToken"/>, the proof must carry its hash (<c>ath</c>).
    /// </summary>
    /// <returns>The proof, or the reason it is invalid.</returns>
    public static (DpopProof? Proof, string? Error) Validate(string? proof, string method, Uri uri, DateTimeOffset now, TimeSpan window, string? accessToken = null)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (string.IsNullOrWhiteSpace(proof))
        {
            return (null, "A DPoP proof is required.");
        }

        var parts = proof.Split('.');
        if (parts.Length != 3 || !TryJson(parts[0], out var header) || !TryJson(parts[1], out var payload) || !TryBase64Url(parts[2], out var signature))
        {
            return (null, "The DPoP proof is not a JWS.");
        }

        using (header)
        using (payload)
        {
            var h = header.RootElement;
            var p = payload.RootElement;

            if (Text(h, "typ") != "dpop+jwt")
            {
                return (null, "The DPoP proof must have typ dpop+jwt.");
            }

            var alg = Text(h, "alg");
            if (alg is null || !Algorithms.Contains(alg, StringComparer.Ordinal))
            {
                return (null, "The DPoP proof's algorithm is not supported.");
            }

            if (!h.TryGetProperty("jwk", out var jwk) || jwk.ValueKind != JsonValueKind.Object || jwk.TryGetProperty("d", out _))
            {
                return (null, "The DPoP proof must carry a public jwk.");
            }

            // The cheap checks first: signature verification is the expensive part.
            if (Text(p, "jti") is not { Length: > 0 and <= MaxJtiLength } jti)
            {
                return (null, "The DPoP proof has no jti, or one that is too long.");
            }

            if (!string.Equals(Text(p, "htm"), method, StringComparison.Ordinal))
            {
                return (null, "The DPoP proof is for another HTTP method.");
            }

            if (Text(p, "htu") is not { } htu || !Uri.TryCreate(htu, UriKind.Absolute, out var proofUri) || !SameTarget(proofUri, uri))
            {
                return (null, "The DPoP proof is for another URL.");
            }

            if (!p.TryGetProperty("iat", out var iatElement) || iatElement.ValueKind != JsonValueKind.Number || !iatElement.TryGetInt64(out var iat))
            {
                return (null, "The DPoP proof has no iat.");
            }

            var nowSeconds = now.ToUnixTimeSeconds();
            var windowSeconds = (long)window.TotalSeconds;
            if (iat > nowSeconds + windowSeconds || iat < nowSeconds - windowSeconds)
            {
                return (null, "The DPoP proof is too old or from the future.");
            }

            var issuedAt = DateTimeOffset.FromUnixTimeSeconds(iat);

            if (accessToken is not null
                && !string.Equals(Text(p, "ath"), Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken))), StringComparison.Ordinal))
            {
                return (null, "The DPoP proof is not for this access token.");
            }

            if (Thumbprint(jwk) is not { } jkt)
            {
                return (null, "The DPoP proof's key is not supported.");
            }

            var signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
            return Verify(alg, jwk, jkt, signed, signature)
                ? (new DpopProof(jkt, jti, issuedAt) { Nonce = Text(p, "nonce") }, null)
                : (null, "The DPoP proof's signature is invalid.");
        }
    }

    /// <summary>The RFC 7638 SHA-256 thumbprint of a public EC or RSA JWK, or null for other key types.</summary>
    public static string? Thumbprint(JsonElement jwk)
    {
        var canonical = Text(jwk, "kty") switch
        {
            "EC" when Text(jwk, "crv") is { } crv && Text(jwk, "x") is { } x && Text(jwk, "y") is { } y =>
                $$"""{"crv":"{{crv}}","kty":"EC","x":"{{x}}","y":"{{y}}"}""",
            "RSA" when Text(jwk, "e") is { } e && Text(jwk, "n") is { } n =>
                $$"""{"e":"{{e}}","kty":"RSA","n":"{{n}}"}""",
            _ => null,
        };
        return canonical is null ? null : Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    /// <summary>Encodes <paramref name="bytes"/> as unpadded base64url (RFC 4648 §5), the encoding JWS segments and <c>ath</c> use.</summary>
    public static string Base64Url(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private static bool Verify(string alg, JsonElement jwk, string thumbprint, byte[] data, byte[] signature)
    {
        try
        {
            switch (alg)
            {
                case "ES256" or "ES384" or "ES512":
                    var curve = Text(jwk, "crv") switch
                    {
                        "P-256" when alg == "ES256" => ECCurve.NamedCurves.nistP256,
                        "P-384" when alg == "ES384" => ECCurve.NamedCurves.nistP384,
                        "P-521" when alg == "ES512" => ECCurve.NamedCurves.nistP521,
                        _ => (ECCurve?)null,
                    };
                    var size = alg switch { "ES384" => 48, "ES512" => 66, _ => 32 };
                    if (curve is null || Text(jwk, "kty") != "EC" || !TryBase64Url(Text(jwk, "x"), out var x) || !TryBase64Url(Text(jwk, "y"), out var y)
                        || x.Length != size || y.Length != size || signature.Length != 2 * size)
                    {
                        return false;
                    }

                    var ecdsa = Rent(thumbprint, () => ECDsa.Create(new ECParameters { Curve = curve.Value, Q = new ECPoint { X = x, Y = y } }));
                    var hash = alg switch { "ES384" => HashAlgorithmName.SHA384, "ES512" => HashAlgorithmName.SHA512, _ => HashAlgorithmName.SHA256 };
                    var valid = ecdsa.VerifyData(data, signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                    Return(thumbprint, ecdsa);
                    return valid;

                default:
                    if (Text(jwk, "kty") != "RSA" || !TryBase64Url(Text(jwk, "n"), out var n) || !TryBase64Url(Text(jwk, "e"), out var e)
                        || e.Length > 4 || ModulusBits(n) is < 2048 or > 4096)
                    {
                        return false;
                    }

                    var rsa = Rent(thumbprint, () => RSA.Create(new RSAParameters { Modulus = n, Exponent = e }));
                    var verified = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, alg == "PS256" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
                    Return(thumbprint, rsa);
                    return verified;
            }
        }
        catch (Exception exception) when (exception is CryptographicException or PlatformNotSupportedException or ArgumentException)
        {
            // Not a valid key: the platform's crypto refuses it in several ways.
            return false;
        }
    }

    /// <summary>An imported instance of the key with <paramref name="thumbprint"/>, or a new one from <paramref name="import"/>.</summary>
    private static TKey Rent<TKey>(string thumbprint, Func<TKey> import)
        where TKey : AsymmetricAlgorithm =>
        ImportedKeys.TryGetValue(thumbprint, out var instances) && instances.TryTake(out var instance) && instance is TKey key ? key : import();

    /// <summary>
    /// Keeps <paramref name="key"/> for the next check of the same key. A failed check doesn't return it (the exception skips
    /// this); a full cache starts over, leaving instances still in use to the garbage collector.
    /// </summary>
    private static void Return(string thumbprint, AsymmetricAlgorithm key)
    {
        if (ImportedKeys.Count >= MaxCachedKeys && !ImportedKeys.ContainsKey(thumbprint))
        {
            ImportedKeys.Clear();
        }

        var instances = ImportedKeys.GetOrAdd(thumbprint, static _ => []);
        if (instances.Count < MaxInstancesPerKey)
        {
            instances.Add(key);
        }
        else
        {
            key.Dispose();
        }
    }

    /// <summary>The modulus size in bits, ignoring leading zero bytes (which would otherwise pass off a small key as a large one).</summary>
    private static int ModulusBits(byte[] modulus)
    {
        var start = 0;
        while (start < modulus.Length && modulus[start] == 0)
        {
            start++;
        }

        return start == modulus.Length ? 0 : ((modulus.Length - start - 1) * 8) + (32 - System.Numerics.BitOperations.LeadingZeroCount((uint)modulus[start]));
    }

    /// <summary>Same scheme, host, port and path (RFC 9449 §4.3: query and fragment are ignored).</summary>
    private static bool SameTarget(Uri proof, Uri request) =>
        string.Equals(proof.Scheme, request.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(proof.IdnHost, request.IdnHost, StringComparison.OrdinalIgnoreCase)
        && proof.Port == request.Port
        && string.Equals(proof.AbsolutePath, request.AbsolutePath, StringComparison.Ordinal);

    private static string? Text(JsonElement element, string property)
    {
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.String)
        {
            return null;
        }

        try
        {
            return value.GetString();
        }
        catch (InvalidOperationException)
        {
            // Not valid UTF-16 (a lone surrogate escape): treated as absent.
            return null;
        }
    }

    private static bool TryJson(string segment, out JsonDocument document)
    {
        document = null!;
        if (!TryBase64Url(segment, out var bytes))
        {
            return false;
        }

        try
        {
            document = JsonDocument.Parse(bytes);
            return document.RootElement.ValueKind == JsonValueKind.Object;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryBase64Url(string? value, out byte[] bytes)
    {
        bytes = [];
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        var base64 = value.Replace('-', '+').Replace('_', '/');
        base64 = base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '=');
        var buffer = new byte[base64.Length];
        if (!Convert.TryFromBase64String(base64, buffer, out var written))
        {
            return false;
        }

        bytes = buffer[..written];
        return true;
    }
}

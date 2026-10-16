using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JeffOps.Authentication.Abstractions.Dpop;

/// <summary>A valid DPoP proof (RFC 9449): the key's thumbprint, and the proof's id and time for replay checks.</summary>
/// <param name="Jkt">The RFC 7638 SHA-256 thumbprint of the proof's public key (what <c>cnf.jkt</c> holds).</param>
/// <param name="Jti">The proof's unique id, for the replay cache.</param>
/// <param name="IssuedAt">When the proof was made.</param>
public sealed record DpopProof(string Jkt, string Jti, DateTimeOffset IssuedAt);

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

    /// <summary>The signature algorithms accepted (and advertised as <c>dpop_signing_alg_values_supported</c>).</summary>
    public static IReadOnlyList<string> Algorithms { get; } = ["ES256", "ES384", "ES512", "PS256", "RS256"];

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

            var signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
            if (!Verify(alg, jwk, signed, signature))
            {
                return (null, "The DPoP proof's signature is invalid.");
            }

            if (Text(p, "jti") is not { Length: > 0 } jti)
            {
                return (null, "The DPoP proof has no jti.");
            }

            if (!string.Equals(Text(p, "htm"), method, StringComparison.Ordinal))
            {
                return (null, "The DPoP proof is for another HTTP method.");
            }

            if (Text(p, "htu") is not { } htu || !Uri.TryCreate(htu, UriKind.Absolute, out var proofUri) || !SameTarget(proofUri, uri))
            {
                return (null, "The DPoP proof is for another URL.");
            }

            if (!p.TryGetProperty("iat", out var iatElement) || !iatElement.TryGetInt64(out var iat))
            {
                return (null, "The DPoP proof has no iat.");
            }

            var issuedAt = DateTimeOffset.FromUnixTimeSeconds(iat);
            if (issuedAt > now + window || issuedAt < now - window)
            {
                return (null, "The DPoP proof is too old or from the future.");
            }

            if (accessToken is not null
                && !string.Equals(Text(p, "ath"), Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken))), StringComparison.Ordinal))
            {
                return (null, "The DPoP proof is not for this access token.");
            }

            var jkt = Thumbprint(jwk);
            return jkt is null ? (null, "The DPoP proof's key is not supported.") : (new DpopProof(jkt, jti, issuedAt), null);
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

    private static bool Verify(string alg, JsonElement jwk, byte[] data, byte[] signature)
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
                    if (curve is null || Text(jwk, "kty") != "EC" || !TryBase64Url(Text(jwk, "x"), out var x) || !TryBase64Url(Text(jwk, "y"), out var y))
                    {
                        return false;
                    }

                    using (var ecdsa = ECDsa.Create(new ECParameters { Curve = curve.Value, Q = new ECPoint { X = x, Y = y } }))
                    {
                        var hash = alg switch { "ES384" => HashAlgorithmName.SHA384, "ES512" => HashAlgorithmName.SHA512, _ => HashAlgorithmName.SHA256 };
                        return ecdsa.VerifyData(data, signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                    }

                default:
                    if (Text(jwk, "kty") != "RSA" || !TryBase64Url(Text(jwk, "n"), out var n) || !TryBase64Url(Text(jwk, "e"), out var e) || n.Length < 256)
                    {
                        return false;
                    }

                    using (var rsa = RSA.Create(new RSAParameters { Modulus = n, Exponent = e }))
                    {
                        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, alg == "PS256" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
                    }
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Same scheme, host, port and path (RFC 9449 §4.3: query and fragment are ignored).</summary>
    private static bool SameTarget(Uri proof, Uri request) =>
        string.Equals(proof.Scheme, request.Scheme, StringComparison.OrdinalIgnoreCase)
        && string.Equals(proof.IdnHost, request.IdnHost, StringComparison.OrdinalIgnoreCase)
        && proof.Port == request.Port
        && string.Equals(proof.AbsolutePath, request.AbsolutePath, StringComparison.Ordinal);

    private static string? Text(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

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

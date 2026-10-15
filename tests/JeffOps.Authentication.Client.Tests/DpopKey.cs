using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Dpop;

namespace JeffOps.Authentication.Client.Tests;

/// <summary>A client's DPoP key: makes proofs (RFC 9449 §4.2) the way a client library would.</summary>
internal sealed class DpopKey : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public Dictionary<string, string> PublicJwk
    {
        get
        {
            var parameters = _key.ExportParameters(includePrivateParameters: false);
            return new() { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = DpopProofValidator.Base64Url(parameters.Q.X!), ["y"] = DpopProofValidator.Base64Url(parameters.Q.Y!) };
        }
    }

    public string Thumbprint => DpopProofValidator.Thumbprint(JsonSerializer.SerializeToElement(PublicJwk))!;

    public string Proof(string method, string url, string? accessToken = null, DateTimeOffset? issuedAt = null, string typ = "dpop+jwt", object? jwkOverride = null)
    {
        var header = new Dictionary<string, object> { ["typ"] = typ, ["alg"] = "ES256", ["jwk"] = jwkOverride ?? PublicJwk };
        var payload = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["htm"] = method,
            ["htu"] = url,
            ["iat"] = (issuedAt ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds(),
        };
        if (accessToken is not null)
        {
            payload["ath"] = DpopProofValidator.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
        }

        var signingInput = $"{Encode(header)}.{Encode(payload)}";
        var signature = _key.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return $"{signingInput}.{DpopProofValidator.Base64Url(signature)}";
    }

    public void Dispose() => _key.Dispose();

    private static string Encode(object value) => DpopProofValidator.Base64Url(JsonSerializer.SerializeToUtf8Bytes(value));
}

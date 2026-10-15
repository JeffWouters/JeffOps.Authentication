using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>
/// A WebAuthn authenticator in code: one P-256 key, "none" attestation, user presence and verification. Enough to drive the
/// token server's passkey ceremonies end to end.
/// </summary>
internal sealed class SoftwareAuthenticator : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private uint _signCount;

    public byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(16);

    public string Origin { get; init; } = "https://localhost";

    public string RpId { get; init; } = "localhost";

    public bool BackupEligible { get; init; }

    /// <summary>Answers <c>navigator.credentials.create()</c> for the creation options JSON.</summary>
    public string Create(string creationOptionsJson)
    {
        using var options = JsonDocument.Parse(creationOptionsJson);
        var challenge = options.RootElement.GetProperty("challenge").GetString()!;
        var clientData = ClientData("webauthn.create", challenge);

        var parameters = _key.ExportParameters(includePrivateParameters: false);
        var coseKey = Cbor.Map(
            (Cbor.Int(1), Cbor.Int(2)),
            (Cbor.Int(3), Cbor.Int(-7)),
            (Cbor.Int(-1), Cbor.Int(1)),
            (Cbor.Int(-2), Cbor.Bytes(parameters.Q.X!)),
            (Cbor.Int(-3), Cbor.Bytes(parameters.Q.Y!)));

        var credentialData = new List<byte>();
        credentialData.AddRange(new byte[16]); // AAGUID
        credentialData.Add((byte)(CredentialId.Length >> 8));
        credentialData.Add((byte)CredentialId.Length);
        credentialData.AddRange(CredentialId);
        credentialData.AddRange(coseKey);

        var authenticatorData = AuthenticatorData(attestedCredential: true, [.. credentialData]);
        var attestationObject = Cbor.Map(
            (Cbor.Text("fmt"), Cbor.Text("none")),
            (Cbor.Text("attStmt"), Cbor.Map()),
            (Cbor.Text("authData"), Cbor.Bytes(authenticatorData)));

        return JsonSerializer.Serialize(new
        {
            id = Base64Url(CredentialId),
            rawId = Base64Url(CredentialId),
            type = "public-key",
            authenticatorAttachment = "platform",
            clientExtensionResults = new { },
            response = new
            {
                clientDataJSON = Base64Url(clientData),
                attestationObject = Base64Url(attestationObject),
                transports = new[] { "internal" },
            },
        });
    }

    /// <summary>Answers <c>navigator.credentials.get()</c> for the request options JSON, as the user <paramref name="userHandle"/>.</summary>
    public string Get(string requestOptionsJson, byte[] userHandle)
    {
        using var options = JsonDocument.Parse(requestOptionsJson);
        var challenge = options.RootElement.GetProperty("challenge").GetString()!;
        var clientData = ClientData("webauthn.get", challenge);
        var authenticatorData = AuthenticatorData(attestedCredential: false, []);
        var signature = _key.SignData([.. authenticatorData, .. SHA256.HashData(clientData)], HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

        return JsonSerializer.Serialize(new
        {
            id = Base64Url(CredentialId),
            rawId = Base64Url(CredentialId),
            type = "public-key",
            authenticatorAttachment = "platform",
            clientExtensionResults = new { },
            response = new
            {
                clientDataJSON = Base64Url(clientData),
                authenticatorData = Base64Url(authenticatorData),
                signature = Base64Url(signature),
                userHandle = Base64Url(userHandle),
            },
        });
    }

    public void Dispose() => _key.Dispose();

    public static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private byte[] ClientData(string type, string challenge) =>
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { type, challenge, origin = Origin, crossOrigin = false }));

    private byte[] AuthenticatorData(bool attestedCredential, byte[] credentialData)
    {
        // UP (0x01) | UV (0x04) | BE (0x08) | AT (0x40)
        var flags = (byte)(0x01 | 0x04 | (BackupEligible ? 0x08 : 0) | (attestedCredential ? 0x40 : 0));
        _signCount++;
        return
        [
            .. SHA256.HashData(Encoding.UTF8.GetBytes(RpId)),
            flags,
            (byte)(_signCount >> 24), (byte)(_signCount >> 16), (byte)(_signCount >> 8), (byte)_signCount,
            .. credentialData,
        ];
    }

    /// <summary>Just enough CBOR (RFC 8949) for attestation objects and COSE keys.</summary>
    private static class Cbor
    {
        public static byte[] Int(long value) => value >= 0 ? Head(0, (ulong)value) : Head(1, (ulong)(-1 - value));

        public static byte[] Bytes(byte[] value) => [.. Head(2, (ulong)value.Length), .. value];

        public static byte[] Text(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            return [.. Head(3, (ulong)bytes.Length), .. bytes];
        }

        public static byte[] Map(params (byte[] Key, byte[] Value)[] entries) =>
            [.. Head(5, (ulong)entries.Length), .. entries.SelectMany(entry => entry.Key.Concat(entry.Value))];

        private static byte[] Head(int major, ulong value) => value switch
        {
            < 24 => [(byte)((major << 5) | (int)value)],
            <= byte.MaxValue => [(byte)((major << 5) | 24), (byte)value],
            <= ushort.MaxValue => [(byte)((major << 5) | 25), (byte)(value >> 8), (byte)value],
            _ => [(byte)((major << 5) | 26), (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value],
        };
    }
}

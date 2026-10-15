using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using JeffOps.Authentication.Application.Abstractions;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Infrastructure.Keys;

/// <summary>Signing certificates for <see cref="CertificateKeyProvider"/>. Bound from <c>JeffOps:TokenServer:SigningCertificates</c>.</summary>
public sealed class SigningCertificateOptions
{
    public const string SectionName = "JeffOps:TokenServer:SigningCertificates";

    /// <summary>Base64 PKCS#12 certificates with private keys, newest first. The first signs; the others stay published.</summary>
    public IList<string> Certificates { get; } = [];

    public string? Password { get; set; }
}

/// <summary>
/// Signing keys from configured PKCS#12 certificates, for deployments that manage keys outside the database. Rotate by
/// putting the new certificate first and keeping the old one until its tokens have expired.
/// </summary>
public sealed class CertificateKeyProvider : ITokenKeyProvider
{
    private readonly Lazy<IReadOnlyList<SigningKey>> _keys;

    public CertificateKeyProvider(IOptions<SigningCertificateOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _keys = new Lazy<IReadOnlyList<SigningKey>>(() => Load(options.Value));
    }

    public event EventHandler? KeysChanged
    {
        add { }
        remove { }
    }

    public IReadOnlyList<SigningKey> GetSigningKeys() => _keys.Value;

    private static IReadOnlyList<SigningKey> Load(SigningCertificateOptions options)
    {
        if (options.Certificates.Count == 0)
        {
            throw new InvalidOperationException($"{SigningCertificateOptions.SectionName}:Certificates must contain at least one certificate.");
        }

        return [.. options.Certificates.Select((base64, index) =>
        {
            using var certificate = X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(base64), options.Password);
            var rsa = certificate.GetRSAPrivateKey()
                ?? throw new InvalidOperationException($"Signing certificate {index} has no RSA private key.");

            // Copy the key out of the certificate so it outlives the certificate object.
            var copy = RSA.Create();
            copy.ImportParameters(rsa.ExportParameters(includePrivateParameters: true));
            return new SigningKey(certificate.Thumbprint, copy, DateTimeOffset.MinValue);
        })];
    }
}

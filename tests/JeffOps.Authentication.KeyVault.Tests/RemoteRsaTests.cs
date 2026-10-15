using System.Security.Claims;
using System.Security.Cryptography;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JeffOps.Authentication.KeyVault.Tests;

public sealed class RemoteRsaTests
{
    [Fact]
    public async Task Tokens_signed_remotely_validate_with_the_published_public_key()
    {
        using var vaultKey = RSA.Create(2048);
        using var publicKey = RSA.Create();
        publicKey.ImportParameters(vaultKey.ExportParameters(false));
        using var remote = new RemoteRsa(publicKey, new FakeCryptographyClient(vaultKey));

        var handler = new JsonWebTokenHandler();
        var token = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "https://issuer.test",
            Subject = new ClaimsIdentity([new Claim("sub", "someone")]),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(remote) { KeyId = "v1" }, SecurityAlgorithms.RsaSha256),
        });

        using var verification = RSA.Create();
        verification.ImportParameters(vaultKey.ExportParameters(false));
        var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuer = "https://issuer.test",
            ValidateAudience = false,
            IssuerSigningKey = new RsaSecurityKey(verification) { KeyId = "v1" },
        });

        result.IsValid.ShouldBeTrue(result.Exception?.Message);
    }

    [Fact]
    public void The_private_key_never_leaves_the_vault()
    {
        using var vaultKey = RSA.Create(2048);
        using var remote = new RemoteRsa(RSA.Create(), new FakeCryptographyClient(vaultKey));

        Should.Throw<CryptographicException>(() => remote.ExportParameters(includePrivateParameters: true));
        Should.Throw<NotSupportedException>(() => remote.Decrypt([1, 2, 3], RSAEncryptionPadding.OaepSHA256));
    }

    [Fact]
    public void Unsupported_algorithms_are_refused()
    {
        using var vaultKey = RSA.Create(2048);
        using var remote = new RemoteRsa(RSA.Create(), new FakeCryptographyClient(vaultKey));

        Should.Throw<CryptographicException>(() => remote.SignHash(new byte[20], HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1));
    }

    /// <summary>Signs locally where Key Vault would sign remotely.</summary>
    private sealed class FakeCryptographyClient(RSA key) : CryptographyClient
    {
        public override SignResult Sign(SignatureAlgorithm algorithm, byte[] digest, CancellationToken cancellationToken = default)
        {
            algorithm.ShouldBe(SignatureAlgorithm.RS256);
            return Azure.Security.KeyVault.Keys.CryptographyModelFactory.SignResult("https://vault.test/keys/k/v1", key.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), algorithm);
        }
    }
}

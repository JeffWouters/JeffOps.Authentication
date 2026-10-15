using System.Security.Cryptography;

namespace JeffOps.Authentication.Application.Abstractions;

/// <summary>
/// A token-signing key. <see cref="Key"/> may be an RSA whose private operations happen remotely (an HSM, Key Vault): only
/// <see cref="RSA.SignHash(byte[], HashAlgorithmName, RSASignaturePadding)"/> and the public parameters are needed.
/// </summary>
/// <param name="KeyId">The <c>kid</c> published in JWKS and stamped on tokens.</param>
/// <param name="Key">The key.</param>
/// <param name="ActivatesAt">When it starts signing; until then it is only published.</param>
public sealed record SigningKey(string KeyId, RSA Key, DateTimeOffset ActivatesAt);

/// <summary>
/// Supplies the token-signing keys (docs/DESIGN.md §7.5). Implementations: database (default), certificate, Key Vault.
/// </summary>
public interface ITokenKeyProvider
{
    /// <summary>Every published key, newest first. The protocol layer signs with the newest active one.</summary>
    IReadOnlyList<SigningKey> GetSigningKeys();

    /// <summary>Raised when the key set changes (rotation, retirement, activation); the server reloads without restarting (I4).</summary>
    event EventHandler? KeysChanged;
}

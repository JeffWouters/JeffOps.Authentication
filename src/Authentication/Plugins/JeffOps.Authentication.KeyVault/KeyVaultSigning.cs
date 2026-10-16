using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.KeyVault;

/// <summary>Key Vault signing. Bound from <see cref="SectionName"/>.</summary>
public sealed class KeyVaultSigningOptions
{
    /// <summary>The configuration section the options bind from.</summary>
    public const string SectionName = "JeffOps:TokenServer:KeyVault";

    /// <summary>The vault or Managed HSM URL.</summary>
    [Required]
    public Uri? VaultUri { get; set; }

    /// <summary>The RSA key to sign with. Rotate it in Key Vault (for example with a rotation policy).</summary>
    [Required]
    public string? KeyName { get; set; }

    /// <summary>How often to check for a new key version.</summary>
    public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromHours(1);
}

/// <summary>Registers Azure Key Vault as the source of token signing keys.</summary>
public static class KeyVaultSigningExtensions
{
    /// <summary>
    /// Signs tokens with an RSA key in Azure Key Vault or Managed HSM: the private key never leaves the vault. Uses the
    /// registered <see cref="TokenCredential"/>, or <see cref="DefaultAzureCredential"/>. A new key version is picked up
    /// without a restart; the previous version stays published so its tokens keep validating.
    /// </summary>
    public static AuthenticationBuilder AddKeyVaultSigning(this AuthenticationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddOptions<KeyVaultSigningOptions>()
            .Bind(builder.Configuration.GetSection(KeyVaultSigningOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();
        builder.Services.AddSingleton<KeyVaultKeyProvider>();
        builder.Services.AddHostedService(provider => provider.GetRequiredService<KeyVaultKeyProvider>());
        builder.Services.AddSingleton<ITokenKeyProvider>(provider => provider.GetRequiredService<KeyVaultKeyProvider>());
        return builder.UseSigningKeyProvider<KeyVaultKeyProvider>();
    }
}

/// <summary>Publishes the current Key Vault key version (and the one before it) and signs remotely.</summary>
internal sealed partial class KeyVaultKeyProvider(
    IOptions<KeyVaultSigningOptions> options,
    IServiceProvider services,
    TimeProvider time,
    ILogger<KeyVaultKeyProvider> logger) : BackgroundService, ITokenKeyProvider
{
    private readonly Lock _gate = new();
    private IReadOnlyList<SigningKey>? _keys;
    private KeyClient? _keyClient;
    private TokenCredential? _credential;

    public event EventHandler? KeysChanged;

    public IReadOnlyList<SigningKey> GetSigningKeys()
    {
        lock (_gate)
        {
            return _keys ??= [Load(previous: null)];
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(options.Value.RefreshInterval, time);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                Refresh();
            }
#pragma warning disable CA1031 // A failed check is logged and retried; the current key keeps signing.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                LogRefreshFailed(logger, exception);
            }
        }
    }

    internal void Refresh()
    {
        bool changed;
        lock (_gate)
        {
            var current = _keys?.FirstOrDefault();
            var latest = Load(previous: current);
            changed = current is null || latest.KeyId != current.KeyId;
            if (changed)
            {
                _keys = current is null ? [latest] : [latest, current];
                LogNewVersion(logger, latest.KeyId);
            }
        }

        if (changed)
        {
            KeysChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    private SigningKey Load(SigningKey? previous)
    {
        var settings = options.Value;
        _credential ??= services.GetService<TokenCredential>() ?? new DefaultAzureCredential();
        _keyClient ??= new KeyClient(settings.VaultUri, _credential);

        KeyVaultKey key = _keyClient.GetKey(settings.KeyName);
        var version = key.Properties.Version ?? settings.KeyName!;
        if (previous?.KeyId == version)
        {
            return previous;
        }

        var publicKey = key.Key.ToRSA(includePrivateParameters: false);
        var rsa = new RemoteRsa(publicKey, new CryptographyClient(key.Id, _credential));
        return new SigningKey(version, rsa, DateTimeOffset.MinValue);
    }

    [LoggerMessage(EventId = 8401, Level = LogLevel.Information, Message = "Signing with Key Vault key version {KeyId}.")]
    private static partial void LogNewVersion(ILogger logger, string keyId);

    [LoggerMessage(EventId = 8402, Level = LogLevel.Warning, Message = "Checking Key Vault for a new signing key version failed; the current version keeps signing.")]
    private static partial void LogRefreshFailed(ILogger logger, Exception exception);
}

/// <summary>
/// An RSA key whose public half is local and whose signing happens in Key Vault. Token signing needs nothing else; every
/// operation that would need the private key locally refuses.
/// </summary>
internal sealed class RemoteRsa : RSA
{
    private readonly RSA _publicKey;
    private readonly CryptographyClient _client;

    public RemoteRsa(RSA publicKey, CryptographyClient client)
    {
        _publicKey = publicKey;
        _client = client;
        KeySizeValue = publicKey.KeySize;
        LegalKeySizesValue = [new KeySizes(publicKey.KeySize, publicKey.KeySize, 0)];
    }

    public override RSAParameters ExportParameters(bool includePrivateParameters) =>
        includePrivateParameters
            ? throw new CryptographicException("The private key stays in Key Vault.")
            : _publicKey.ExportParameters(false);

    public override void ImportParameters(RSAParameters parameters) =>
        throw new NotSupportedException("A Key Vault key can't be replaced locally.");

    public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(padding);

        var algorithm = (hashAlgorithm.Name, padding.Mode) switch
        {
            ("SHA256", RSASignaturePaddingMode.Pkcs1) => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.RS256,
            ("SHA384", RSASignaturePaddingMode.Pkcs1) => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.RS384,
            ("SHA512", RSASignaturePaddingMode.Pkcs1) => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.RS512,
            ("SHA256", RSASignaturePaddingMode.Pss) => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.PS256,
            ("SHA384", RSASignaturePaddingMode.Pss) => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.PS384,
            ("SHA512", RSASignaturePaddingMode.Pss) => Azure.Security.KeyVault.Keys.Cryptography.SignatureAlgorithm.PS512,
            _ => throw new CryptographicException($"Unsupported signature algorithm {hashAlgorithm.Name}/{padding.Mode}."),
        };

        return _client.Sign(algorithm, hash).Signature;
    }

    public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding) =>
        _publicKey.VerifyHash(hash, signature, hashAlgorithm, padding);

    public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding) =>
        throw new NotSupportedException("Key Vault signing keys are not used for decryption.");

    public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding) => _publicKey.Encrypt(data, padding);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _publicKey.Dispose();
        }

        base.Dispose(disposing);
    }
}

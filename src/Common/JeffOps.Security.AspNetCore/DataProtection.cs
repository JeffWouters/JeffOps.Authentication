using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.StackExchangeRedis;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace JeffOps.Security.AspNetCore;

/// <summary>
/// Data Protection for a JeffOps host. Bound from <see cref="SectionName"/>. The key ring protects session cookies,
/// token-signing keys at rest and BFF sessions, so outside Development it must be encrypted at rest with a key-encryption
/// key (KEK); a host without one fails startup instead of persisting plaintext keys (docs/DESIGN.md §16, I7).
/// </summary>
public sealed class DataProtectionSettings
{
    /// <summary>The configuration section the settings bind from.</summary>
    public const string SectionName = "JeffOps:DataProtection";

    /// <summary>Isolates this application's keys; hosts that must read each other's payloads share it.</summary>
    public string? ApplicationName { get; set; }

    /// <summary>The KEK: a base64-encoded PKCS#12 certificate with its private key.</summary>
    public string? KekCertificate { get; set; }

    /// <summary>The password of <see cref="KekCertificate"/>, if it has one.</summary>
    public string? KekCertificatePassword { get; set; }

    /// <summary>Earlier KEK certificates (base64 PKCS#12), kept so keys they encrypted stay readable during rotation.</summary>
    public IList<string> PreviousKekCertificates { get; } = [];

    /// <summary>Password of the earlier certificates, when they share one.</summary>
    public string? PreviousKekCertificatesPassword { get; set; }
}

/// <summary>Registers Data Protection for a JeffOps host.</summary>
public static class DataProtectionExtensions
{
    /// <summary>
    /// Adds Data Protection with the application name and certificate KEK from <see cref="DataProtectionSettings"/>.
    /// Choose where keys persist on the returned builder, for example <see cref="PersistKeysToRedis"/>.
    /// </summary>
    public static IDataProtectionBuilder AddJeffOpsDataProtection(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<DataProtectionSettings>()
            .Bind(configuration.GetSection(DataProtectionSettings.SectionName))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<DataProtectionSettings>, DataProtectionSettingsValidator>();

        var builder = services.AddDataProtection();

        services.AddOptions<DataProtectionOptions>()
            .Configure<IOptions<DataProtectionSettings>>((options, settings) =>
            {
                if (!string.IsNullOrWhiteSpace(settings.Value.ApplicationName))
                {
                    options.ApplicationDiscriminator = settings.Value.ApplicationName;
                }
            });

        // The certificates are loaded now, from the configuration at hand, so a malformed KEK fails at registration with a
        // clear message. Whether one is REQUIRED depends on the environment and is checked at startup by the validator.
        var settings = configuration.GetSection(DataProtectionSettings.SectionName).Get<DataProtectionSettings>() ?? new DataProtectionSettings();
        var decryption = DecryptionCertificates(settings).ToArray();
        if (LoadKek(settings) is { } kek)
        {
            builder.ProtectKeysWithCertificate(kek);
        }

        if (decryption.Length > 0)
        {
            builder.UnprotectKeysWithAnyCertificate(decryption);
        }

        return builder;
    }

    /// <summary>Persists the key ring in Redis under <paramref name="key"/>, using the registered <see cref="IConnectionMultiplexer"/>.</summary>
    public static IDataProtectionBuilder PersistKeysToRedis(this IDataProtectionBuilder builder, string key)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        builder.Services.AddOptions<KeyManagementOptions>()
            .Configure<IServiceProvider>((options, provider) =>
            {
                var redis = provider.GetRequiredService<IConnectionMultiplexer>();
                options.XmlRepository = new RedisXmlRepository(() => redis.GetDatabase(), key);
            });
        return builder;
    }

    internal static X509Certificate2? LoadKek(DataProtectionSettings settings) =>
        string.IsNullOrWhiteSpace(settings.KekCertificate)
            ? null
            : Load(settings.KekCertificate, settings.KekCertificatePassword, "KekCertificate");

    private static X509Certificate2 Load(string base64, string? password, string setting)
    {
        try
        {
            return X509CertificateLoader.LoadPkcs12(Convert.FromBase64String(base64), password);
        }
        catch (Exception exception) when (exception is FormatException or System.Security.Cryptography.CryptographicException)
        {
            throw new InvalidOperationException($"{DataProtectionSettings.SectionName}:{setting} could not be loaded: {exception.Message}", exception);
        }
    }

    private static IEnumerable<X509Certificate2> DecryptionCertificates(DataProtectionSettings settings)
    {
        if (LoadKek(settings) is { } current)
        {
            yield return current;
        }

        foreach (var previous in settings.PreviousKekCertificates.Where(value => !string.IsNullOrWhiteSpace(value)))
        {
            yield return Load(previous, settings.PreviousKekCertificatesPassword, "PreviousKekCertificates");
        }
    }

    private sealed class DataProtectionSettingsValidator(IHostEnvironment environment) : IValidateOptions<DataProtectionSettings>
    {
        public ValidateOptionsResult Validate(string? name, DataProtectionSettings options)
        {
            if (string.IsNullOrWhiteSpace(options.KekCertificate))
            {
                return environment.IsDevelopment()
                    ? ValidateOptionsResult.Success
                    : ValidateOptionsResult.Fail(
                        $"{DataProtectionSettings.SectionName}:KekCertificate is required outside Development; the key ring would otherwise persist unencrypted.");
            }

            try
            {
                using var certificate = LoadKek(options)!;
                return certificate.HasPrivateKey
                    ? ValidateOptionsResult.Success
                    : ValidateOptionsResult.Fail($"{DataProtectionSettings.SectionName}:KekCertificate has no private key.");
            }
            catch (InvalidOperationException exception)
            {
                return ValidateOptionsResult.Fail(exception.Message);
            }
        }
    }
}

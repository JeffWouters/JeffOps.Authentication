using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Federation.Saml;

/// <summary>What a provider's metadata says: its signing certificates and its sign-in and logout URLs.</summary>
internal sealed record IdpMetadata(IReadOnlyList<X509Certificate2> SigningCertificates, Uri? SingleSignOnUrl, Uri? SingleLogoutUrl, DateTimeOffset FetchedAt);

/// <summary>The last good metadata of each provider configured with an <see cref="SamlProviderOptions.IdpMetadataUrl"/>.</summary>
internal sealed class SamlMetadata
{
    private readonly ConcurrentDictionary<string, IdpMetadata> _byProvider = new(StringComparer.Ordinal);

    public IdpMetadata? For(string provider) => _byProvider.GetValueOrDefault(provider);

    public void Set(string provider, IdpMetadata metadata) => _byProvider[provider] = metadata;
}

/// <summary>
/// Downloads the metadata of providers configured with an <see cref="SamlProviderOptions.IdpMetadataUrl"/> at startup and
/// then every <see cref="SamlProviderOptions.MetadataRefreshInterval"/>, so a provider can roll its signing certificate
/// without a configuration change here. Metadata comes over HTTPS only and must name the configured entity id; a failed
/// download keeps the last good copy.
/// </summary>
internal sealed partial class SamlMetadataRefresher(
    IEnumerable<SamlProviderRegistration> registrations,
    IOptionsMonitor<SamlProviderOptions> options,
    SamlMetadata metadata,
    IHttpClientFactory httpClientFactory,
    TimeProvider time,
    ILogger<SamlMetadataRefresher> logger) : BackgroundService
{
    public const string HttpClientName = "JeffOps.Saml.Metadata";

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        // The first download before the server starts taking sign-ins; the refresh loop runs in the background.
        await RefreshAllAsync(cancellationToken).ConfigureAwait(false);
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = registrations.Select(registration => options.Get(registration.Name))
            .Where(settings => settings.IdpMetadataUrl is not null)
            .Select(settings => settings.MetadataRefreshInterval)
            .DefaultIfEmpty(Timeout.InfiniteTimeSpan)
            .Min();
        if (interval == Timeout.InfiniteTimeSpan)
        {
            return;
        }

        using var timer = new PeriodicTimer(interval, time);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            await RefreshAllAsync(stoppingToken).ConfigureAwait(false);
        }
    }

    internal async Task RefreshAllAsync(CancellationToken cancellationToken)
    {
        foreach (var registration in registrations)
        {
            var settings = options.Get(registration.Name);
            if (settings.IdpMetadataUrl is { } url)
            {
                await RefreshAsync(registration.Name, settings, url, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task RefreshAsync(string provider, SamlProviderOptions settings, Uri url, CancellationToken cancellationToken)
    {
        try
        {
            if (url.Scheme != Uri.UriSchemeHttps)
            {
                throw new InvalidOperationException("Metadata is only downloaded over HTTPS.");
            }

            using var client = httpClientFactory.CreateClient(HttpClientName);
            var xml = await client.GetStringAsync(url, cancellationToken).ConfigureAwait(false);
            var descriptor = new EntityDescriptor().ReadIdPSsoDescriptor(xml);
            if (!string.Equals(descriptor.EntityId, settings.IdpEntityId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"The metadata names entity '{descriptor.EntityId}', not the configured '{settings.IdpEntityId}'.");
            }

            var idp = descriptor.IdPSsoDescriptor ?? throw new InvalidOperationException("The metadata describes no identity provider.");
            var certificates = idp.SigningCertificates?.ToList() ?? [];
            if (certificates.Count == 0)
            {
                throw new InvalidOperationException("The metadata names no signing certificate.");
            }

            metadata.Set(provider, new IdpMetadata(
                certificates,
                idp.SingleSignOnServices?.FirstOrDefault(service => service.Binding?.OriginalString == Redirect)?.Location,
                idp.SingleLogoutServices?.FirstOrDefault(service => service.Binding?.OriginalString == Redirect)?.Location,
                time.GetUtcNow()));
        }
#pragma warning disable CA1031 // A failed refresh keeps the last good metadata; it is logged, never fatal.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogFailed(logger, exception, provider);
        }
    }

    private const string Redirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

    [LoggerMessage(EventId = 8510, Level = LogLevel.Warning, Message = "Refreshing the metadata of SAML provider {Provider} failed; the last good copy stays in use.")]
    private static partial void LogFailed(ILogger logger, Exception exception, string provider);
}

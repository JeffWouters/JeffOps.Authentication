using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Federation.Saml;

/// <summary>
/// What a provider's metadata says: its signing certificates and its sign-in and logout URLs, with where it came from
/// (<paramref name="Source"/>) and the entity it names.
/// </summary>
internal sealed record IdpMetadata(
    IReadOnlyList<X509Certificate2> SigningCertificates,
    Uri? SingleSignOnUrl,
    Uri? SingleLogoutUrl,
    DateTimeOffset FetchedAt,
    Uri Source,
    string EntityId);

/// <summary>The last good metadata of each provider configured with an <see cref="SamlProviderOptions.IdpMetadataUrl"/>.</summary>
internal sealed class SamlMetadata(TimeProvider time)
{
    private readonly ConcurrentDictionary<string, IdpMetadata> _byProvider = new(StringComparer.Ordinal);

    /// <summary>
    /// The provider's metadata, only while it matches its current settings (the same metadata URL and entity id) and is
    /// younger than <see cref="SamlProviderOptions.MetadataMaxAge"/>: a changed or removed URL stops trusting the old
    /// certificates at once.
    /// </summary>
    public IdpMetadata? For(string provider, SamlProviderOptions settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return _byProvider.GetValueOrDefault(provider) is { } current
            && current.Source == settings.IdpMetadataUrl
            && string.Equals(current.EntityId, settings.IdpEntityId, StringComparison.Ordinal)
            && time.GetUtcNow() - current.FetchedAt <= settings.MetadataMaxAge
                ? current
                : null;
    }

    public void Set(string provider, IdpMetadata metadata) => _byProvider[provider] = metadata;

    public void Remove(string provider) => _byProvider.TryRemove(provider, out _);
}

/// <summary>
/// Downloads the metadata of providers configured with an <see cref="SamlProviderOptions.IdpMetadataUrl"/> at startup and
/// then every <see cref="SamlProviderOptions.MetadataRefreshInterval"/>, so a provider can roll its signing certificate
/// without a configuration change here. Metadata comes over HTTPS only and must name the configured entity id; a failed
/// download keeps the last good copy.
/// </summary>
internal sealed class SamlMetadataRefresher(
    IEnumerable<SamlProviderRegistration> registrations,
    IOptionsMonitor<SamlProviderOptions> options,
    SamlMetadataClient client,
    TimeProvider time) : BackgroundService
{
    public const string HttpClientName = SamlMetadataClient.HttpClientName;

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
            if (settings.IdpMetadataUrl is not null)
            {
                await client.RefreshAsync(registration.Name, settings, SamlMetadataClient.HttpClientName, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}

/// <summary>Downloads and checks provider metadata, for configured providers and for the ones tenants register.</summary>
internal sealed partial class SamlMetadataClient(SamlMetadata metadata, IHttpClientFactory httpClientFactory, TimeProvider time, ILogger<SamlMetadataClient> logger)
{
    public const string HttpClientName = "JeffOps.Saml.Metadata";

    /// <summary>The client for tenants' metadata URLs: public addresses only, no redirects (<see cref="PublicNetwork"/>).</summary>
    public const string TenantHttpClientName = "JeffOps.Saml.TenantMetadata";

    /// <summary>How long a download may take, headers and body.</summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    /// <summary>After a failed download of a tenant's metadata, how long before the next try.</summary>
    public static readonly TimeSpan RetryAfterFailure = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, Lazy<Task>> _inFlight = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _failedAt = new(StringComparer.Ordinal);

    /// <summary>
    /// Downloads a tenant provider's metadata unless a copy younger than its refresh interval is at hand. Requests for the
    /// same provider share one download, and after a failure the next waits <see cref="RetryAfterFailure"/>: anonymous
    /// requests can't make this server fetch over and over.
    /// </summary>
    public async Task EnsureAsync(string provider, SamlProviderOptions settings, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (settings.IdpMetadataUrl is null)
        {
            metadata.Remove(provider);
            return;
        }

        var now = time.GetUtcNow();
        if ((metadata.For(provider, settings) is { } current && now - current.FetchedAt < settings.MetadataRefreshInterval)
            || (_failedAt.TryGetValue(provider, out var failed) && now - failed < RetryAfterFailure))
        {
            return;
        }

        var download = _inFlight.GetOrAdd(provider, name => new Lazy<Task>(() => DownloadOnceAsync(name, settings)));
        await download.Value.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task DownloadOnceAsync(string provider, SamlProviderOptions settings)
    {
        try
        {
            // Not the first caller's token: a caller giving up doesn't cancel the download others wait for.
            if (await RefreshAsync(provider, settings, TenantHttpClientName, CancellationToken.None).ConfigureAwait(false))
            {
                _failedAt.TryRemove(provider, out _);
            }
            else
            {
                _failedAt[provider] = time.GetUtcNow();
            }
        }
        finally
        {
            _inFlight.TryRemove(provider, out _);
        }
    }

    /// <summary>Downloads and checks the metadata; true when it was stored, false when it failed (logged).</summary>
    public async Task<bool> RefreshAsync(string provider, SamlProviderOptions settings, string clientName, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (settings.IdpMetadataUrl is not { } url)
        {
            metadata.Remove(provider);
            return false;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(Timeout);
        try
        {
            if (url.Scheme != Uri.UriSchemeHttps)
            {
                throw new InvalidOperationException("Metadata is only downloaded over HTTPS.");
            }

            using var client = httpClientFactory.CreateClient(clientName);
            using var response = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            var xml = await PublicNetwork.ReadLimitedAsync(response, MaxMetadataBytes, timeout.Token).ConfigureAwait(false);

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
                time.GetUtcNow(),
                url,
                descriptor.EntityId));
            return true;
        }
#pragma warning disable CA1031 // A failed refresh keeps the last good metadata; it is logged, never fatal.
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
        {
            LogFailed(logger, exception, provider);
            return false;
        }
    }

    private const string Redirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    private const int MaxMetadataBytes = 1024 * 1024;

    [LoggerMessage(EventId = 8510, Level = LogLevel.Warning, Message = "Refreshing the metadata of SAML provider {Provider} failed; the last good copy stays in use.")]
    private static partial void LogFailed(ILogger logger, Exception exception, string provider);
}

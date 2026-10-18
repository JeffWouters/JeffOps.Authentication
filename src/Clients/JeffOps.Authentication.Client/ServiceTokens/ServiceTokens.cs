using System.ComponentModel.DataAnnotations;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Client.ServiceTokens;

/// <summary>
/// The client-credentials identity of this service. Bound from <see cref="SectionName"/>. There are no defaults: a
/// missing client id or secret fails startup instead of falling back to a well-known value (docs/DESIGN.md §17, I6).
/// </summary>
public sealed class ServiceTokenOptions
{
    /// <summary>The configuration section the options bind from: <c>JeffOps:ServiceToken</c>.</summary>
    public const string SectionName = "JeffOps:ServiceToken";

    /// <summary>The token server's token endpoint. Required.</summary>
    [Required]
    public Uri? TokenEndpoint { get; set; }

    /// <summary>This service's client id at the token server. Required.</summary>
    [Required]
    public string? ClientId { get; set; }

    /// <summary>This service's client secret. Required.</summary>
    [Required]
    public string? ClientSecret { get; set; }

    /// <summary>Space-separated scopes to request; optional.</summary>
    public string? Scope { get; set; }

    /// <summary>How long before expiry a cached token is replaced.</summary>
    public TimeSpan RefreshBeforeExpiry { get; set; } = TimeSpan.FromMinutes(1);
}

/// <summary>
/// Acquires this service's access token with the client-credentials grant and caches it until shortly before it expires.
/// One request at a time refreshes it; concurrent callers wait for that request.
/// </summary>
public sealed class ServiceTokenProvider(IHttpClientFactory httpClientFactory, IOptions<ServiceTokenOptions> options, TimeProvider time) : IDisposable
{
    /// <summary>The name of the HTTP client that calls the token endpoint.</summary>
    public const string HttpClientName = "JeffOps.ServiceToken";

    private readonly SemaphoreSlim _gate = new(1, 1);

    // The token and when to replace it, published together: a reader never sees a new token with an old time or the reverse.
    private volatile CachedToken? _cached;

    /// <summary>
    /// This service's access token, cached or newly acquired. Throws <see cref="HttpRequestException"/> when the token
    /// endpoint refuses the request.
    /// </summary>
    public async Task<string> GetTokenAsync(CancellationToken cancellationToken = default)
    {
        if (_cached is { } cached && time.GetUtcNow() < cached.RefreshAt)
        {
            return cached.Token;
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_cached is { } refreshed && time.GetUtcNow() < refreshed.RefreshAt)
            {
                return refreshed.Token;
            }

            var settings = options.Value;
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = settings.ClientId!,
                ["client_secret"] = settings.ClientSecret!,
            };
            if (!string.IsNullOrWhiteSpace(settings.Scope))
            {
                form["scope"] = settings.Scope;
            }

            using var content = new FormUrlEncodedContent(form);
            using var response = await httpClientFactory.CreateClient(HttpClientName)
                .PostAsync(settings.TokenEndpoint, content, cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException(
                    $"The token endpoint refused the client-credentials request for '{settings.ClientId}' ({(int)response.StatusCode}).",
                    inner: null,
                    response.StatusCode);
            }

            var token = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(token?.AccessToken))
            {
                throw new InvalidOperationException("The token endpoint returned no access token.");
            }

            _cached = new CachedToken(token.AccessToken, time.GetUtcNow().AddSeconds(token.ExpiresIn).Subtract(settings.RefreshBeforeExpiry));
            return token.AccessToken;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public void Dispose() => _gate.Dispose();

    private sealed record CachedToken(string Token, DateTimeOffset RefreshAt);

    private sealed record TokenResponse(
        [property: JsonPropertyName("access_token")] string? AccessToken,
        [property: JsonPropertyName("expires_in")] int ExpiresIn);
}

/// <summary>Attaches the service's bearer token to outgoing requests that carry no Authorization header.</summary>
public sealed class ServiceTokenHandler(ServiceTokenProvider tokens) : DelegatingHandler
{
    /// <inheritdoc />
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.Headers.Authorization is null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await tokens.GetTokenAsync(cancellationToken).ConfigureAwait(false));
        }

        return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}

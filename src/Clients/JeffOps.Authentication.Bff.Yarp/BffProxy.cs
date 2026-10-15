using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Transforms;

namespace JeffOps.Authentication.Bff.Yarp;

public static class BffProxyExtensions
{
    /// <summary>
    /// Removes the <c>Cookie</c> header from every proxied request: backends authenticate with the bearer token the BFF
    /// attached, and must never receive the session cookie.
    /// </summary>
    public static IReverseProxyBuilder AddBffTransforms(this IReverseProxyBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddTransforms(context => context.AddRequestHeaderRemove("Cookie"));
    }

    /// <summary>
    /// Exchanges personal access tokens at the edge (docs/DESIGN.md §9): a request with <c>Authorization: Bearer pat_…</c>
    /// reaches backends with a short-lived JWT instead. Options bind from <see cref="PatExchangeOptions.SectionName"/>.
    /// </summary>
    public static IServiceCollection AddJeffOpsPatExchange(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<PatExchangeOptions>()
            .Bind(configuration.GetSection(PatExchangeOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddDataProtection();
        services.AddHttpClient(PatExchanger.HttpClientName);
        services.TryAddSingleton<PatExchanger>();
        return services;
    }

    /// <summary>Exchanges PATs on incoming requests. Register before the proxy, after the BFF middleware.</summary>
    public static IApplicationBuilder UseJeffOpsPatExchange(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<PatExchangeMiddleware>();
    }
}

/// <summary>The edge's client identity for exchanging PATs. Bound from <c>JeffOps:PatExchange</c>.</summary>
public sealed class PatExchangeOptions
{
    public const string SectionName = "JeffOps:PatExchange";

    [Required]
    public Uri? TokenEndpoint { get; set; }

    [Required]
    public string? ClientId { get; set; }

    [Required]
    public string? ClientSecret { get; set; }

    public string GrantType { get; set; } = "urn:jeffops:grant-type:pat";

    /// <summary>The prefix PATs start with; other bearer tokens pass through untouched.</summary>
    public string Prefix { get; set; } = "pat_";

    public string? Scope { get; set; }

    /// <summary>How long a refused PAT is remembered as refused, so a leaked bad token can't hammer the token server.</summary>
    public TimeSpan NegativeCacheDuration { get; set; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// Exchanges a PAT for a JWT and caches the result under the PAT's SHA-256 (never the PAT itself), encrypted with Data
/// Protection in the distributed cache and briefly in memory. Refusals are cached for a short time; outages aren't cached.
/// </summary>
public sealed partial class PatExchanger(
    IHttpClientFactory httpClientFactory,
    IDistributedCache cache,
    IMemoryCache local,
    IDataProtectionProvider dataProtection,
    IOptions<PatExchangeOptions> options,
    ILogger<PatExchanger> logger)
{
    public const string HttpClientName = "JeffOps.PatExchange";
    private const string Refused = "refused";

    private readonly IDataProtector _protector = dataProtection.CreateProtector("JeffOps.PatExchange");

    public enum Outcome
    {
        Exchanged,
        Refused,
        Unavailable,
    }

    public async Task<(Outcome Outcome, string? AccessToken)> ExchangeAsync(string pat, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pat);

        var key = "jeffops:pat:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(pat)));
        if (local.TryGetValue(key, out string? hot) && hot is not null)
        {
            return hot == Refused ? (Outcome.Refused, null) : (Outcome.Exchanged, hot);
        }

        var cached = await cache.GetStringAsync(key, cancellationToken).ConfigureAwait(false);
        if (cached is not null)
        {
            var value = cached == Refused ? Refused : _protector.Unprotect(cached);
            local.Set(key, value, TimeSpan.FromSeconds(30));
            return value == Refused ? (Outcome.Refused, null) : (Outcome.Exchanged, value);
        }

        var settings = options.Value;
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = settings.GrantType,
            ["pat"] = pat,
            ["client_id"] = settings.ClientId!,
            ["client_secret"] = settings.ClientSecret!,
        };
        if (!string.IsNullOrWhiteSpace(settings.Scope))
        {
            form["scope"] = settings.Scope;
        }

        HttpResponseMessage response;
        try
        {
            using var content = new FormUrlEncodedContent(form);
            response = await httpClientFactory.CreateClient(HttpClientName).PostAsync(settings.TokenEndpoint, content, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException exception)
        {
            LogUnavailable(logger, exception);
            return (Outcome.Unavailable, null);
        }

        using (response)
        {
            if ((int)response.StatusCode >= 500 || response.StatusCode is HttpStatusCode.TooManyRequests)
            {
                return (Outcome.Unavailable, null);
            }

            if (!response.IsSuccessStatusCode)
            {
                await cache.SetStringAsync(key, Refused, new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = settings.NegativeCacheDuration }, cancellationToken).ConfigureAwait(false);
                local.Set(key, Refused, settings.NegativeCacheDuration);
                return (Outcome.Refused, null);
            }

            var token = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(token?.AccessToken))
            {
                return (Outcome.Unavailable, null);
            }

            // Cache until shortly before the token expires, so a backend never receives an expired one.
            var lifetime = TimeSpan.FromSeconds(Math.Max(0, token.ExpiresIn - 30));
            if (lifetime > TimeSpan.Zero)
            {
                await cache.SetStringAsync(key, _protector.Protect(token.AccessToken), new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = lifetime }, cancellationToken).ConfigureAwait(false);
                local.Set(key, token.AccessToken, lifetime < TimeSpan.FromSeconds(30) ? lifetime : TimeSpan.FromSeconds(30));
            }

            return (Outcome.Exchanged, token.AccessToken);
        }
    }

    [LoggerMessage(EventId = 9121, Level = LogLevel.Warning, Message = "Exchanging a personal access token failed: the token server is unreachable.")]
    private static partial void LogUnavailable(ILogger logger, Exception exception);

    private sealed record TokenResponse(
        [property: JsonPropertyName("access_token")] string? AccessToken,
        [property: JsonPropertyName("expires_in")] int ExpiresIn);
}

/// <summary>Replaces a PAT bearer with the exchanged JWT; answers 401 for a refused PAT and 503 when the token server is down.</summary>
public sealed class PatExchangeMiddleware(RequestDelegate next, PatExchanger exchanger, IOptions<PatExchangeOptions> options)
{
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var header = context.Request.Headers.Authorization.ToString();
        var prefix = "Bearer " + options.Value.Prefix;
        if (header.StartsWith(prefix, StringComparison.Ordinal))
        {
            var (outcome, token) = await exchanger.ExchangeAsync(header["Bearer ".Length..].Trim(), context.RequestAborted).ConfigureAwait(false);
            switch (outcome)
            {
                case PatExchanger.Outcome.Exchanged:
                    context.Request.Headers.Authorization = "Bearer " + token;
                    break;
                case PatExchanger.Outcome.Refused:
                    context.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return;
                default:
                    context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                    return;
            }
        }

        await next(context).ConfigureAwait(false);
    }
}

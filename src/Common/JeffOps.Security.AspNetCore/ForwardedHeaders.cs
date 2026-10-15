using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace JeffOps.Security.AspNetCore;

/// <summary>
/// Which proxies in front of the service are trusted to report the client address and scheme. Bound from
/// <see cref="SectionName"/>.
/// </summary>
public sealed class TrustedProxyOptions
{
    public const string SectionName = "JeffOps:ForwardedHeaders";

    /// <summary>How many proxy hops to trust. 0 means no proxy: the socket peer is the client.</summary>
    public int TrustedProxyHops { get; set; }

    /// <summary>Acknowledges that there really is no proxy in front of the service (required outside Development with 0 hops).</summary>
    public bool NoTrustedProxy { get; set; }

    /// <summary>IP addresses of trusted proxies.</summary>
    public IList<string> KnownProxies { get; } = [];

    /// <summary>CIDR ranges of trusted proxies.</summary>
    public IList<string> KnownNetworks { get; } = [];
}

public static class ForwardedHeadersExtensions
{
    /// <summary>
    /// Configures forwarded-header handling from <see cref="TrustedProxyOptions"/>. Fails startup outside Development when
    /// no hop count is configured and <see cref="TrustedProxyOptions.NoTrustedProxy"/> isn't set: behind an ingress, every
    /// client would otherwise share the proxy's address and per-client rate limits collapse into one bucket, silently.
    /// Invalid addresses also fail startup instead of trusting nothing, or everything.
    /// </summary>
    public static IServiceCollection AddJeffOpsForwardedHeaders(this IServiceCollection services, Microsoft.Extensions.Configuration.IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<TrustedProxyOptions>()
            .Bind(configuration.GetSection(TrustedProxyOptions.SectionName))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<TrustedProxyOptions>, TrustedProxyOptionsValidator>();
        services.AddOptions<ForwardedHeadersOptions>()
            .Configure<IOptions<TrustedProxyOptions>>((forwarded, trusted) => Apply(forwarded, trusted.Value));
        return services;
    }

    /// <summary>
    /// Applies forwarded headers when proxies are trusted. Must run before anything reads the client address or
    /// <c>Request.IsHttps</c> (rate limiting, secure cookies, HSTS).
    /// </summary>
    public static IApplicationBuilder UseJeffOpsForwardedHeaders(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var options = app.ApplicationServices.GetRequiredService<IOptions<ForwardedHeadersOptions>>().Value;
        return options.ForwardedHeaders == Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.None ? app : app.UseForwardedHeaders();
    }

    internal static void Apply(ForwardedHeadersOptions options, TrustedProxyOptions trusted)
    {
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();

        if (trusted.TrustedProxyHops <= 0)
        {
            options.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.None;
            return;
        }

        // Proto as well as For: behind TLS termination, Request.IsHttps decides Secure cookies and HSTS.
        options.ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor
            | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto;
        options.ForwardLimit = trusted.TrustedProxyHops;
        foreach (var proxy in trusted.KnownProxies)
        {
            options.KnownProxies.Add(IPAddress.Parse(proxy));
        }

        foreach (var network in trusted.KnownNetworks)
        {
            options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(network));
        }
    }

    private sealed class TrustedProxyOptionsValidator(IHostEnvironment environment) : IValidateOptions<TrustedProxyOptions>
    {
        public ValidateOptionsResult Validate(string? name, TrustedProxyOptions options)
        {
            var failures = new List<string>();

            if (options.TrustedProxyHops <= 0 && !options.NoTrustedProxy && !environment.IsDevelopment())
            {
                failures.Add(
                    $"{TrustedProxyOptions.SectionName}:TrustedProxyHops must be > 0 outside Development. If no proxy is in front of " +
                    $"this service, set {TrustedProxyOptions.SectionName}:NoTrustedProxy=true to acknowledge.");
            }

            failures.AddRange(options.KnownProxies
                .Where(proxy => !IPAddress.TryParse(proxy, out _))
                .Select(proxy => $"'{proxy}' is not an IP address."));
            failures.AddRange(options.KnownNetworks
                .Where(network => !System.Net.IPNetwork.TryParse(network, out _))
                .Select(network => $"'{network}' is not a CIDR network."));

            return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
        }
    }
}

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace JeffOps.Security.AspNetCore;

/// <summary>Registers and applies the JeffOps ASP.NET Core hardening baseline.</summary>
public static class SecurityServiceCollectionExtensions
{
    /// <summary>
    /// Adds the JeffOps ASP.NET Core hardening baseline: security headers, trusted forwarded headers, the CORS policy and
    /// the edge origin lock. Data Protection is added separately with <c>AddJeffOpsDataProtection</c>, because only hosts
    /// that persist keys need it. Outside Development, an <c>AllowedHosts</c> of <c>*</c> fails startup: the request host
    /// builds absolute URLs (redirects, locations, origins), so it must be one the service answers to. Pair with
    /// <see cref="UseJeffOpsSecurity"/>.
    /// </summary>
    public static IServiceCollection AddJeffOpsSecurity(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<SecurityHeadersOptions>().Bind(configuration.GetSection(SecurityHeadersOptions.SectionName));
        services.AddOptions<OriginLockOptions>().Bind(configuration.GetSection(OriginLockOptions.SectionName));
        services.AddOptions<AllowedHostsOptions>()
            .Configure(options => options.AllowedHosts = configuration[AllowedHostsOptions.Key])
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<AllowedHostsOptions>, AllowedHostsValidator>();
        services.AddJeffOpsForwardedHeaders(configuration);
        services.AddJeffOpsCors(configuration);
        return services;
    }

    /// <summary>
    /// Runs the hardening middleware in the required order: origin lock, forwarded headers (before anything reads the client
    /// address or scheme), security headers, CORS. Call before authentication.
    /// </summary>
    public static IApplicationBuilder UseJeffOpsSecurity(this IApplicationBuilder app) =>
        app.UseJeffOpsOriginLock()
            .UseJeffOpsForwardedHeaders()
            .UseJeffOpsSecurityHeaders()
            .UseJeffOpsCors();

    /// <summary>The host's <c>AllowedHosts</c> setting, as host filtering reads it.</summary>
    internal sealed class AllowedHostsOptions
    {
        public const string Key = "AllowedHosts";

        public string? AllowedHosts { get; set; }
    }

    private sealed class AllowedHostsValidator(IHostEnvironment environment) : IValidateOptions<AllowedHostsOptions>
    {
        public ValidateOptionsResult Validate(string? name, AllowedHostsOptions options) =>
            !environment.IsDevelopment()
            && (options.AllowedHosts ?? string.Empty).Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Contains("*")
                ? ValidateOptionsResult.Fail($"{AllowedHostsOptions.Key} can't be '*' outside Development: list the host names this service answers to.")
                : ValidateOptionsResult.Success;
    }
}

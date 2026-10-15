using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Security.AspNetCore;

public static class SecurityServiceCollectionExtensions
{
    /// <summary>
    /// Adds the JeffOps ASP.NET Core hardening baseline: security headers, trusted forwarded headers, the CORS policy and
    /// the edge origin lock. Data Protection is added separately with <c>AddJeffOpsDataProtection</c>, because only hosts
    /// that persist keys need it. Pair with <see cref="UseJeffOpsSecurity"/>.
    /// </summary>
    public static IServiceCollection AddJeffOpsSecurity(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<SecurityHeadersOptions>().Bind(configuration.GetSection(SecurityHeadersOptions.SectionName));
        services.AddOptions<OriginLockOptions>().Bind(configuration.GetSection(OriginLockOptions.SectionName));
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
}

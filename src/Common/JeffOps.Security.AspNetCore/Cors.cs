using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Security.AspNetCore;

/// <summary>Registers and applies the JeffOps CORS policy.</summary>
public static class CorsExtensions
{
    /// <summary>The name of the CORS policy added by <see cref="AddJeffOpsCors"/>.</summary>
    public const string PolicyName = "JeffOps";

    /// <summary>The configuration section that holds <c>AllowedOrigins</c>.</summary>
    public const string SectionName = "JeffOps:Cors";

    /// <summary>
    /// Adds the CORS policy <see cref="PolicyName"/>: the origins in <c>JeffOps:Cors:AllowedOrigins</c> with credentials
    /// (needed for an HttpOnly session cookie), any method and header, and <c>Retry-After</c> exposed so clients can back off.
    /// With no origins configured it allows none: fail closed.
    /// </summary>
    public static IServiceCollection AddJeffOpsCors(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var origins = configuration.GetSection($"{SectionName}:AllowedOrigins").Get<string[]>() ?? [];

        return services.AddCors(options => options.AddPolicy(PolicyName, policy =>
        {
            if (origins.Length > 0)
            {
                policy.WithOrigins(origins).AllowCredentials();
            }
            else
            {
                policy.SetIsOriginAllowed(_ => false);
            }

            policy.AllowAnyMethod().AllowAnyHeader().WithExposedHeaders("Retry-After");
        }));
    }

    /// <summary>Applies the <see cref="PolicyName"/> CORS policy to every request.</summary>
    public static IApplicationBuilder UseJeffOpsCors(this IApplicationBuilder app) => app.UseCors(PolicyName);
}

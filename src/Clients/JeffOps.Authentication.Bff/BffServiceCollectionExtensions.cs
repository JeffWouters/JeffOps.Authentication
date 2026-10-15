using JeffOps.Authentication.Bff.Endpoints;
using JeffOps.Authentication.Bff.Middleware;
using JeffOps.Authentication.Bff.Sessions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Bff;

public static class BffServiceCollectionExtensions
{
    /// <summary>
    /// Adds the backend-for-frontend (docs/DESIGN.md §9.1): a confidential OpenID Connect client of the token server (code
    /// flow with PKCE via the OpenIddict client), server-side sessions in <see cref="Microsoft.Extensions.Caching.Distributed.IDistributedCache"/>
    /// protected with Data Protection, single-flight token refresh, and back-channel logout. Register a distributed cache
    /// (Redis in production) and a shared Data Protection key ring for multiple replicas.
    /// Options bind from <see cref="BffOptions.SectionName"/>.
    /// </summary>
    public static IServiceCollection AddJeffOpsBff(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<BffOptions>()
            .Bind(configuration.GetSection(BffOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        var settings = configuration.GetSection(BffOptions.SectionName).Get<BffOptions>() ?? new BffOptions();

        services.TryAddSingleton(TimeProvider.System);
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddDataProtection();
        services.TryAddSingleton<BffSessionStore>();
        services.TryAddSingleton<BffSessionManager>();

        var client = services.AddOpenIddict().AddClient();
        client.AllowAuthorizationCodeFlow().AllowRefreshTokenFlow();

        // No server-side token store in a BFF: state tokens are short-lived and protected with Data Protection.
        client.DisableTokenStorage();
        client.AddEphemeralEncryptionKey().AddEphemeralSigningKey();
        client.UseDataProtection();
        client.UseSystemNetHttp();
        client.UseAspNetCore().EnableRedirectionEndpointPassthrough();
        client.SetRedirectionEndpointUris(BffPaths.Callback.TrimStart('/'));

        if (settings.Authority is not null && !string.IsNullOrWhiteSpace(settings.ClientId))
        {
            var registration = new OpenIddictClientRegistration
            {
                Issuer = settings.Authority,
                ClientId = settings.ClientId,
                ClientSecret = settings.ClientSecret,
                RedirectUri = new Uri(BffPaths.Callback.TrimStart('/'), UriKind.Relative),
            };
            registration.Scopes.Add(Scopes.OpenId);
            registration.Scopes.Add(Scopes.OfflineAccess);
            foreach (var scope in settings.Scopes)
            {
                registration.Scopes.Add(scope);
            }

            client.AddRegistration(registration);
        }

        services.AddOptions<OpenIddictClientAspNetCoreOptions>()
            .Configure<IHostEnvironment>((aspNetCore, environment) => aspNetCore.DisableTransportSecurityRequirement = environment.IsDevelopment());

        return services;
    }

    /// <summary>
    /// Adds the BFF middleware in order: CSRF protection, then cookie-to-bearer. Call after authentication setup and before
    /// the proxy or the API endpoints.
    /// </summary>
    public static IApplicationBuilder UseJeffOpsBff(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);
        return app.UseMiddleware<CsrfMiddleware>().UseMiddleware<CookieToBearerMiddleware>();
    }

    /// <summary>Maps <c>/bff/login</c>, <c>/bff/callback</c>, <c>/bff/logout</c>, <c>/bff/me</c> and <c>/bff/backchannel-logout</c>.</summary>
    public static IEndpointRouteBuilder MapJeffOpsBff(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        BffEndpoints.Map(endpoints);
        return endpoints;
    }
}

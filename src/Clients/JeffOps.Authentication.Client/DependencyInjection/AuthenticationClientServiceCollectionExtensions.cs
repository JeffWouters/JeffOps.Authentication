using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Client.Access;
using JeffOps.Authentication.Client.ServiceTokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Client.DependencyInjection;

/// <summary>Registers token validation, service tokens and access-context propagation in a resource service.</summary>
public static class AuthenticationClientServiceCollectionExtensions
{
    /// <summary>The JWT <c>typ</c> of access tokens (RFC 9068), the only type accepted as a bearer credential.</summary>
    public const string AccessTokenType = "at+jwt";

    /// <summary>
    /// Adds platform token validation to a resource service (docs/DESIGN.md §16):
    /// <list type="bullet">
    /// <item>JWT bearer against <see cref="AuthenticationClientOptions.Authority"/>, with audience validation always on,
    /// HTTPS metadata outside Development, raw claim names (no inbound mapping), and only access tokens accepted
    /// (<c>typ</c> <see cref="AccessTokenType"/>), so an ID token is never a bearer credential.</item>
    /// <item>A fallback policy requiring an authenticated user on every endpoint; opt out with <c>AllowAnonymous()</c>.</item>
    /// <item>DPoP (RFC 9449): proofs are checked for every DPoP-bound token (see <see cref="AuthenticationClientOptions.Dpop"/>).</item>
    /// <item><see cref="ICurrentUser"/> and <see cref="IAccessContextAccessor"/> for the current request.</item>
    /// </list>
    /// Options bind from <see cref="AuthenticationClientOptions.SectionName"/> and are validated at startup.
    /// </summary>
    public static AuthenticationBuilder AddJeffOpsAuthenticationClient(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<AuthenticationClientOptions>()
            .Bind(configuration.GetSection(AuthenticationClientOptions.SectionName))
            .ValidateDataAnnotations()
            .Validate(options => options.Audiences.Any(audience => !string.IsNullOrWhiteSpace(audience)), "At least one audience is required.")
            .ValidateOnStart();

        services.TryAddSingleton(ClaimNames.Default);
        services.AddHttpContextAccessor();
        services.TryAddScoped<ICurrentUser, HttpCurrentUser>();
        services.RemoveAll<IAccessContextAccessor>();
        services.AddScoped<IAccessContextAccessor, HttpAccessContextAccessor>();

        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<AuthenticationClientOptions>, ClaimNames, IHostEnvironment>((jwt, client, names, environment) =>
            {
                var settings = client.Value;
                jwt.Authority = settings.Authority;
                jwt.RequireHttpsMetadata = settings.RequireHttpsMetadata ?? !environment.IsDevelopment();
                jwt.MapInboundClaims = false;
                jwt.TokenValidationParameters.ValidateAudience = true;
                jwt.TokenValidationParameters.ValidAudiences = [.. settings.Audiences.Where(audience => !string.IsNullOrWhiteSpace(audience))];

                // Access tokens only (RFC 9068): an ID token whose audience happens to match is not a bearer credential.
                jwt.TokenValidationParameters.ValidTypes = [AccessTokenType, "application/" + AccessTokenType];
                jwt.TokenValidationParameters.NameClaimType = names.Name;
                jwt.TokenValidationParameters.RoleClaimType = "role";
            });

        // After the host's own configuration, so its events are kept and wrapped.
        services.AddMemoryCache();
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<Abstractions.Replay.IReplayCache>(provider => new Abstractions.Replay.MemoryReplayCache(
            provider.GetService<TimeProvider>(), provider.GetRequiredService<IOptions<AuthenticationClientOptions>>().Value.DpopReplayCapacity));
        services.TryAddSingleton<DpopKeyQuota>();
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .PostConfigure<IOptions<AuthenticationClientOptions>, TimeProvider>((jwt, client, time) => DpopValidation.Attach(jwt, client.Value.Dpop, time, client.Value.DpopNonces));

        services.AddAuthorizationBuilder()
            .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());

        return services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
    }

    /// <summary>
    /// Adds this service's client-credentials identity. Options bind from <see cref="ServiceTokenOptions.SectionName"/>
    /// and are required at startup. Attach tokens to an HTTP client with <see cref="AddServiceToken"/>.
    /// </summary>
    public static IServiceCollection AddJeffOpsServiceTokens(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<ServiceTokenOptions>()
            .Bind(configuration.GetSection(ServiceTokenOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.TryAddSingleton(TimeProvider.System);
        services.AddHttpClient(ServiceTokenProvider.HttpClientName);
        services.TryAddSingleton<ServiceTokenProvider>();
        services.TryAddTransient<ServiceTokenHandler>();
        return services;
    }

    /// <summary>Attaches this service's token to requests of the client. Requires <see cref="AddJeffOpsServiceTokens"/>.</summary>
    public static IHttpClientBuilder AddServiceToken(this IHttpClientBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddHttpMessageHandler<ServiceTokenHandler>();
    }

    /// <summary>Propagates the caller's tenant to the callee in trusted internal headers.</summary>
    public static IHttpClientBuilder AddAccessContextPropagation(this IHttpClientBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddHttpContextAccessor();
        builder.Services.TryAddSingleton(ClaimNames.Default);
        builder.Services.AddOptions<AuthenticationClientOptions>();
        builder.Services.TryAddTransient<AccessContextPropagationHandler>();
        return builder.AddHttpMessageHandler<AccessContextPropagationHandler>();
    }
}

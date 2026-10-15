using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authorization.AspNetCore.Data;
using JeffOps.Authorization.AspNetCore.Evaluation;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Ceilings;
using JeffOps.Authorization.Domain.Decisions;
using JeffOps.Authorization.Domain.Permissions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace JeffOps.Authorization.AspNetCore.DependencyInjection;

/// <summary>Returned by <see cref="PermissionAuthorizationServiceCollectionExtensions.AddJeffOpsPermissionAuthorization(IServiceCollection, IConfiguration)"/>.</summary>
/// <param name="Services">The service collection.</param>
/// <param name="ManagementClient">
/// The HTTP client reading the management API. Add authentication here, for example
/// <c>.ManagementClient.AddServiceToken()</c> from <c>JeffOps.Authentication.Client</c>.
/// </param>
public sealed record PermissionAuthorizationBuilder(IServiceCollection Services, IHttpClientBuilder ManagementClient)
{
    /// <summary>Declares this service's permissions; they are pushed to the management registry at startup.</summary>
    public PermissionAuthorizationBuilder AddPermissionRegistration(string source, IReadOnlyList<PermissionDefinition> definitions)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        ArgumentNullException.ThrowIfNull(definitions);

        Services.AddSingleton(new PermissionManifest(source, definitions));
        Services.AddHostedService<PermissionRegistration>();
        return this;
    }
}

public static class PermissionAuthorizationServiceCollectionExtensions
{
    /// <summary>
    /// Adds permission-based authorization for a resource service (docs/DESIGN.md §11.3): the dynamic permission policy
    /// provider, the local decision handler, <see cref="IAuthorizer"/>, the sealed decision cache over
    /// <see cref="Microsoft.Extensions.Caching.Hybrid.HybridCache"/>, the HTTP client for the management read API, cache
    /// invalidation handlers, and problem-details answers for step-up and impersonation refusals.
    /// Options bind from <see cref="PermissionAuthorizationOptions.SectionName"/>.
    /// </summary>
    public static PermissionAuthorizationBuilder AddJeffOpsPermissionAuthorization(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<PermissionAuthorizationOptions>()
            .Bind(configuration.GetSection(PermissionAuthorizationOptions.SectionName));

        services.TryAddSingleton(ClaimNames.Default);
        services.TryAddSingleton(TimeProvider.System);
        services.AddHttpContextAccessor();
        services.TryAddScoped<IAccessContextAccessor, ClaimsAccessContextAccessor>();
        services.AddHybridCache();

        services.TryAddSingleton(provider =>
        {
            var options = provider.GetRequiredService<IOptions<PermissionAuthorizationOptions>>().Value;
            return new AuthorizationPipeline(
                new StepUpPolicy([.. options.SensitivePermissions]),
                new ImpersonationPolicy([.. options.ImpersonationRefusedPermissions]),
                options.BuildDelegationCeiling());
        });

        services.TryAddSingleton<SealedDecisionCache>();
        services.TryAddScoped<IAuthorizationData, CachedAuthorizationData>();
        services.TryAddScoped<AuthorizationEvaluator>();
        services.TryAddScoped<IAuthorizer, Authorizer>();

        var managementClient = services.AddHttpClient(HttpAuthorizationDataSource.HttpClientName, (provider, client) =>
        {
            if (provider.GetRequiredService<IOptions<PermissionAuthorizationOptions>>().Value.ManagementBaseAddress is { } baseAddress)
            {
                client.BaseAddress = baseAddress;
            }
        });
        services.TryAddTransient(provider => new HttpAuthorizationDataSource(
            provider.GetRequiredService<IHttpClientFactory>().CreateClient(HttpAuthorizationDataSource.HttpClientName)));
        services.TryAddTransient<IAuthorizationDataSource>(provider => provider.GetRequiredService<HttpAuthorizationDataSource>());
        services.TryAddTransient<IPermissionRegistry>(provider => provider.GetRequiredService<HttpAuthorizationDataSource>());

        services.AddAuthorization();
        services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
        services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
        services.AddSingleton<Microsoft.AspNetCore.Authorization.IAuthorizationMiddlewareResultHandler, PermissionResultHandler>();
        services.AddTransient<Microsoft.AspNetCore.Hosting.IStartupFilter, RouteRuleValidator>();

        services.TryAddScoped<AuthorizationCacheInvalidator>();
        services.TryAddScoped<IIntegrationEventHandler<RolePermissionsChangedEvent>>(Invalidator);
        services.TryAddScoped<IIntegrationEventHandler<UserRoleAssignedEvent>>(Invalidator);
        services.TryAddScoped<IIntegrationEventHandler<UserRoleRevokedEvent>>(Invalidator);
        services.TryAddScoped<IIntegrationEventHandler<PolicyChangedEvent>>(Invalidator);
        services.TryAddScoped<IIntegrationEventHandler<ScopesChangedEvent>>(Invalidator);

        return new PermissionAuthorizationBuilder(services, managementClient);
    }

    private static AuthorizationCacheInvalidator Invalidator(IServiceProvider provider) =>
        provider.GetRequiredService<AuthorizationCacheInvalidator>();
}

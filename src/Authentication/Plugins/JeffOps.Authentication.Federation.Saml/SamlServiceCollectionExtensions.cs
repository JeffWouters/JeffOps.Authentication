using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Application.Federation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace JeffOps.Authentication.Federation.Saml;

/// <summary>Registers SAML 2.0 identity providers.</summary>
public static class SamlServiceCollectionExtensions
{
    /// <summary>
    /// Adds a SAML 2.0 identity provider named <paramref name="name"/> (docs/DESIGN.md §8.3). Settings bind from
    /// <c>JeffOps:TokenServer:Federation:Saml:{name}</c>; <paramref name="configure"/> can add to them. Map the endpoints with
    /// <c>MapJeffOpsSaml</c> and give the provider this server's metadata at <c>signin/saml/{name}/metadata</c>.
    /// </summary>
    public static AuthenticationBuilder AddSamlProvider(this AuthenticationBuilder builder, string name, Action<SamlProviderOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var services = builder.Services;
        var options = services.AddOptions<SamlProviderOptions>(name).Bind(builder.Configuration.GetSection($"{SamlProviderOptions.SectionName}:{name}"));
        if (configure is not null)
        {
            options.Configure(configure);
        }

        options.Validate(
            settings => settings.IdpEntityId is not null
                && (settings.IdpMetadataUrl is not null || (settings.IdpSingleSignOnUrl is not null && settings.IdpSigningCertificates.Count > 0)),
            $"SAML provider '{name}' needs IdpEntityId, and IdpMetadataUrl or IdpSingleSignOnUrl with at least one IdpSigningCertificates entry.").ValidateOnStart();

        AddSharedServices(builder);
        services.AddSingleton(new SamlProviderRegistration(name));
        return builder;
    }

    /// <summary>
    /// Lets tenants register their own SAML providers (through the Enterprise module's <c>enterprise/providers</c> API, once
    /// an operator allows the tenant): their sign-in, assertion and logout endpoints are served under <c>signin/saml/tenant-{id}</c>
    /// by <c>MapJeffOpsSaml</c>. Not needed when configured providers are added with <see cref="AddSamlProvider"/>, which
    /// enables them too. This server's certificates for them bind from <see cref="SamlTenantProviderOptions.SectionName"/>.
    /// </summary>
    public static AuthenticationBuilder AddSamlTenantProviders(this AuthenticationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        AddSharedServices(builder);
        return builder;
    }

    /// <summary>The services every SAML provider shares, registered once.</summary>
    private static void AddSharedServices(AuthenticationBuilder builder)
    {
        var services = builder.Services;
        if (services.Any(descriptor => descriptor.ServiceType == typeof(SharedServicesMarker)))
        {
            return;
        }

        services.AddSingleton<SharedServicesMarker>();
        services.AddMemoryCache();
        services.AddDataProtection();
        services.TryAddSingleton<SamlMetadata>();
        services.TryAddSingleton<SamlMetadataClient>();
        services.AddHttpClient(SamlMetadataClient.HttpClientName).ConfigureHttpClient(client => client.Timeout = SamlMetadataClient.Timeout);

        // Tenants' metadata URLs: public addresses only (SSRF), no redirects.
        services.AddHttpClient(SamlMetadataClient.TenantHttpClientName)
            .ConfigureHttpClient(client => client.Timeout = SamlMetadataClient.Timeout)
            .ConfigurePrimaryHttpMessageHandler(PublicNetwork.Handler);
        services.AddOptions<SamlTenantProviderOptions>().Bind(builder.Configuration.GetSection(SamlTenantProviderOptions.SectionName));
        services.AddHostedService<SamlMetadataRefresher>();
        services.TryAddSingleton<SamlProviders>();
        services.TryAddScoped<SamlServices>();
        services.AddSingleton<IExternalSignOut, SamlSignOut>();
        services.AddSingleton<IExternalIdentityMapper>(provider => provider.GetRequiredService<SamlProviders>());
        services.AddSingleton<IExternalProviderChallenge>(provider => provider.GetRequiredService<SamlProviders>());
    }

    private sealed class SharedServicesMarker;
}

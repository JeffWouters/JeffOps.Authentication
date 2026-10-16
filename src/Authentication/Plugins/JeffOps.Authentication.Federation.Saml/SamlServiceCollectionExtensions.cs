using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Application.Federation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;

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
            settings => settings.IdpEntityId is not null && settings.IdpSingleSignOnUrl is not null && settings.IdpSigningCertificates.Count > 0,
            $"SAML provider '{name}' needs IdpEntityId, IdpSingleSignOnUrl and at least one IdpSigningCertificates entry.").ValidateOnStart();

        // The shared services, once for all SAML providers.
        if (!services.Any(descriptor => descriptor.ServiceType == typeof(SamlProviderRegistration)))
        {
            services.AddMemoryCache();
            services.AddDataProtection();
            services.TryAddSingleton<ITokenReplayCache, SamlReplayCache>();
            services.TryAddSingleton<SamlProviders>();
            services.TryAddScoped<SamlServices>();
            services.AddSingleton<IExternalSignOut, SamlSignOut>();
            services.AddSingleton<IExternalIdentityMapper>(provider => provider.GetRequiredService<SamlProviders>());
            services.AddSingleton<IExternalProviderChallenge>(provider => provider.GetRequiredService<SamlProviders>());
        }

        services.AddSingleton(new SamlProviderRegistration(name));
        return builder;
    }
}

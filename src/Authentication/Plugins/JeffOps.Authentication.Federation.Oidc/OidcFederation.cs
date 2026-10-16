using System.Security.Claims;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OpenIddict.Client;
using OpenIddict.Client.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Federation.Oidc;

/// <summary>An upstream OpenID Connect provider. Bound from <c>JeffOps:TokenServer:Federation:Providers:{name}</c>.</summary>
public sealed class OidcProviderOptions
{
    /// <summary>The button label on the login page. Default: the provider's name.</summary>
    public string? DisplayName { get; set; }

    /// <summary>The provider's issuer; its discovery document is fetched from here.</summary>
    public Uri? Authority { get; set; }

    /// <summary>This server's client id at the provider. Required.</summary>
    public string? ClientId { get; set; }

    /// <summary>This server's client secret at the provider, when it issued one. Keep it out of source control.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>Scopes to request besides <c>openid</c>. Default: <c>profile</c>, <c>email</c>.</summary>
    public IList<string> Scopes { get; } = [OpenIddict.Abstractions.OpenIddictConstants.Scopes.Profile, OpenIddict.Abstractions.OpenIddictConstants.Scopes.Email];
}

/// <summary>Registers upstream OpenID Connect providers and the OpenIddict client they share.</summary>
public static class OidcFederationExtensions
{
    /// <summary>The path an upstream provider redirects back to: <c>signin/callback/{provider}</c>.</summary>
    public const string CallbackPathPrefix = "signin/callback/";

    /// <summary>
    /// Adds an upstream OpenID Connect provider (Okta, Auth0, Keycloak, Google, another JeffOps server, …) under
    /// <paramref name="name"/> (docs/DESIGN.md §8.3). The user is sent there from <c>signin/{name}</c> and comes back to
    /// <c>signin/callback/{name}</c>; register that URL at the provider. Accounts are linked on the provider's (issuer, subject).
    /// </summary>
    public static AuthenticationBuilder AddOidcProvider(this AuthenticationBuilder builder, string name, Action<OidcProviderOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var options = new OidcProviderOptions();
        builder.Configuration.GetSection($"{FederationOptions.SectionName}:Providers:{name}").Bind(options);
        configure?.Invoke(options);

        if (options.Authority is null || string.IsNullOrWhiteSpace(options.ClientId))
        {
            throw new InvalidOperationException($"OIDC provider '{name}' needs an Authority and a ClientId.");
        }

        var registration = new OpenIddictClientRegistration
        {
            Issuer = options.Authority,
            ProviderName = name,
            ProviderDisplayName = options.DisplayName ?? name,
            ClientId = options.ClientId,
            ClientSecret = options.ClientSecret,
            RedirectUri = new Uri(CallbackPathPrefix + name, UriKind.Relative),
        };
        registration.Scopes.Add(Scopes.OpenId);
        foreach (var scope in options.Scopes)
        {
            registration.Scopes.Add(scope);
        }

        builder.AddOpenIddictClient().AddRegistration(registration);
        builder.Services.AddSingleton<IExternalIdentityMapper>(provider => new OidcIdentityMapper(
            new ExternalProviderInfo(name, options.DisplayName ?? name),
            provider.GetRequiredService<IOptions<FederationOptions>>()));
        return builder;
    }

    /// <summary>
    /// The OpenIddict client shared by every provider plug-in, set up once: authorization code flow, redirect passthrough to
    /// <c>signin/callback/{provider}</c>, outgoing HTTP, and state tokens protected with Data Protection so a callback can
    /// land on any replica that shares the key ring.
    /// </summary>
    public static OpenIddictClientBuilder AddOpenIddictClient(this AuthenticationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var client = builder.Services.AddOpenIddict().AddClient();
        if (builder.Services.Any(descriptor => descriptor.ServiceType == typeof(OpenIddictClientMarker)))
        {
            return client;
        }

        builder.Services.AddSingleton<OpenIddictClientMarker>();
        builder.Services.AddDataProtection();

        client.AllowAuthorizationCodeFlow();

        // State tokens are protected with Data Protection; these keys only satisfy the client's configuration checks.
        client.AddEphemeralEncryptionKey().AddEphemeralSigningKey();
        client.UseDataProtection();
        client.UseSystemNetHttp();
        client.UseAspNetCore().EnableRedirectionEndpointPassthrough();

        builder.Services.AddOptions<OpenIddictClientOptions>()
            .PostConfigure(options =>
            {
                foreach (var registration in options.Registrations.Where(registration => registration.RedirectUri is not null))
                {
                    if (!options.RedirectionEndpointUris.Contains(registration.RedirectUri!))
                    {
                        options.RedirectionEndpointUris.Add(registration.RedirectUri!);
                    }
                }
            });
        builder.Services.AddOptions<OpenIddictClientAspNetCoreOptions>()
            .Configure<IHostEnvironment>((aspNetCore, environment) => aspNetCore.DisableTransportSecurityRequirement = environment.IsDevelopment());

        return client;
    }

    private sealed class OpenIddictClientMarker;
}

/// <summary>Maps standard OpenID Connect claims to an <see cref="ExternalIdentity"/>.</summary>
public sealed class OidcIdentityMapper(ExternalProviderInfo provider, IOptions<FederationOptions> options) : IExternalIdentityMapper
{
    /// <inheritdoc />
    public IReadOnlyCollection<ExternalProviderInfo> Providers { get; } = [provider];

    /// <inheritdoc />
    public Result<ExternalIdentity> Map(string provider, ClaimsPrincipal providerClaims)
    {
        ArgumentNullException.ThrowIfNull(providerClaims);

        var subject = providerClaims.FindFirst(Claims.Subject);
        var issuer = providerClaims.FindFirst(Claims.Issuer)?.Value ?? subject?.Issuer;
        if (subject is null || string.IsNullOrWhiteSpace(issuer) || issuer == ClaimsIdentity.DefaultIssuer)
        {
            return Error.Unauthorized("provider_response_invalid", "The provider did not identify the user.");
        }

        return new ExternalIdentity(
            provider,
            new ExternalLoginKey(issuer, subject.Value),
            providerClaims.FindFirst(Claims.Email)?.Value,
            bool.TryParse(providerClaims.FindFirst(Claims.EmailVerified)?.Value, out var verified) && verified,
            providerClaims.FindFirst(Claims.Name)?.Value,
            Strength(providerClaims, options.Value));
    }

    /// <summary>The <c>amr</c> methods, plus multi-factor when an <c>acr</c>/<c>acrs</c> value is configured as multi-factor.</summary>
    public static AuthenticationStrength Strength(ClaimsPrincipal providerClaims, FederationOptions options)
    {
        ArgumentNullException.ThrowIfNull(providerClaims);
        ArgumentNullException.ThrowIfNull(options);

        var strength = new AuthenticationStrength(providerClaims.FindAll(Claims.AuthenticationMethodReference).Select(claim => claim.Value));
        var contexts = providerClaims.FindAll(Claims.AuthenticationContextReference).Concat(providerClaims.FindAll("acrs")).Select(claim => claim.Value);
        return contexts.Any(context => options.MultiFactorAuthenticationContexts.Contains(context, StringComparer.OrdinalIgnoreCase))
            ? strength.WithMultiFactor()
            : strength;
    }
}

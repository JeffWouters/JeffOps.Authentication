using System.Security.Claims;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Federation.Oidc;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Federation.Entra;

/// <summary>Microsoft Entra ID sign-in. Bound from <c>JeffOps:TokenServer:Federation:Providers:{name}</c>.</summary>
public sealed class EntraOptions
{
    /// <summary>The button label on the login page. Default: <c>Microsoft</c>.</summary>
    public string DisplayName { get; set; } = "Microsoft";

    /// <summary>The app registration's client id.</summary>
    public string? ClientId { get; set; }

    /// <summary>The app registration's client secret, when it uses one. Keep it out of source control.</summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Which directories may sign in: <c>organizations</c> (any work or school account, the default), <c>common</c> (also
    /// personal Microsoft accounts), <c>consumers</c>, or one tenant id for a single-tenant deployment.
    /// </summary>
    public string Tenant { get; set; } = "organizations";

    /// <summary>
    /// Scopes to request besides <c>openid</c>. Default (null or empty): <c>email</c> and <c>profile</c>. Use <c>profile</c> alone
    /// with an app registration that tenants consented to without <c>email</c>, so reusing it asks no one for consent again; the
    /// account's email then comes from <c>preferred_username</c>.
    /// </summary>
    public IList<string>? Scopes { get; set; }
}

/// <summary>Registers Microsoft Entra ID as an external identity provider.</summary>
public static class EntraFederationExtensions
{
    /// <summary>
    /// Adds Microsoft Entra ID sign-in under <paramref name="name"/> (default <c>entra</c>), redirecting back to
    /// <c>signin/callback/{name}</c> — register that URL on the app registration. Accounts are linked on the directory and
    /// object id (<c>tid</c>, <c>oid</c>), never on email. Add the optional <c>amr</c> claim to the app registration's ID
    /// token so multi-factor sign-ins are recognised, or list the authentication contexts that require MFA in
    /// <c>JeffOps:TokenServer:Federation:MultiFactorAuthenticationContexts</c>.
    /// </summary>
    public static AuthenticationBuilder AddEntra(this AuthenticationBuilder builder, string name = "entra", Action<EntraOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var options = new EntraOptions();
        builder.Configuration.GetSection($"{FederationOptions.SectionName}:Providers:{name}").Bind(options);
        configure?.Invoke(options);

        if (string.IsNullOrWhiteSpace(options.ClientId))
        {
            throw new InvalidOperationException($"Entra provider '{name}' needs a ClientId.");
        }

        builder.AddOpenIddictClient().UseWebProviders().AddMicrosoft(microsoft =>
        {
            microsoft.SetProviderName(name)
                .SetProviderDisplayName(options.DisplayName)
                .SetClientId(options.ClientId)
                .SetTenant(options.Tenant)
                .SetRedirectUri(OidcFederationExtensions.CallbackPathPrefix + name)
                .AddScopes(options.Scopes is { Count: > 0 } scopes ? [.. scopes] : [Scopes.Email, Scopes.Profile]);

            if (!string.IsNullOrEmpty(options.ClientSecret))
            {
                microsoft.SetClientSecret(options.ClientSecret);
            }
        });

        builder.Services.AddSingleton<IExternalIdentityMapper>(provider => new EntraIdentityMapper(
            new ExternalProviderInfo(name, options.DisplayName),
            provider.GetRequiredService<IOptions<FederationOptions>>()));
        return builder;
    }
}

/// <summary>Maps Entra ID claims to an <see cref="ExternalIdentity"/>.</summary>
public sealed class EntraIdentityMapper(ExternalProviderInfo provider, IOptions<FederationOptions> options) : IExternalIdentityMapper
{
    private const string TenantIdClaim = "tid";
    private const string ObjectIdClaim = "oid";

    /// <inheritdoc />
    public IReadOnlyCollection<ExternalProviderInfo> Providers { get; } = [provider];

    /// <inheritdoc />
    public Result<ExternalIdentity> Map(string provider, ClaimsPrincipal providerClaims)
    {
        ArgumentNullException.ThrowIfNull(providerClaims);

        var tenant = providerClaims.FindFirst(TenantIdClaim)?.Value;
        var objectId = providerClaims.FindFirst(ObjectIdClaim)?.Value;
        if (string.IsNullOrWhiteSpace(tenant) || string.IsNullOrWhiteSpace(objectId))
        {
            return Error.Unauthorized("provider_response_invalid", "Microsoft did not identify the directory and user (tid, oid).");
        }

        // Entra's email claim isn't verified for every account type, so it is used for contact only, never for linking.
        var email = providerClaims.FindFirst(Claims.Email)?.Value ?? providerClaims.FindFirst(Claims.PreferredUsername)?.Value;

        return new ExternalIdentity(
            provider,
            new ExternalLoginKey($"https://login.microsoftonline.com/{tenant}/v2.0", objectId),
            email,
            EmailVerified: false,
            providerClaims.FindFirst(Claims.Name)?.Value,
            OidcIdentityMapper.Strength(providerClaims, options.Value))
        {
            DirectoryId = tenant,
        };
    }
}

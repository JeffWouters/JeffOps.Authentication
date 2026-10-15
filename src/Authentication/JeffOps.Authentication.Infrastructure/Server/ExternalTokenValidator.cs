using System.Collections.Concurrent;
using JeffOps.Authentication.Application.Features.Grants.WorkloadIdentity;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// Validates workload tokens against their issuer's OpenID Connect discovery document and keys (cached and refreshed per
/// issuer, HTTPS only). Signature, issuer, audience and lifetime are all checked; a token without <c>exp</c> is refused.
/// </summary>
internal sealed class ExternalTokenValidator(IHttpClientFactory http, TimeProvider time) : IExternalTokenValidator
{
    public const string HttpClientName = "JeffOps.WorkloadIdentity";

    private readonly ConcurrentDictionary<Uri, ConfigurationManager<OpenIdConnectConfiguration>> _configurations = new();

    public async Task<ExternalToken?> ValidateAsync(string token, Uri issuer, string audience, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(issuer);
        if (issuer.Scheme != Uri.UriSchemeHttps)
        {
            return null;
        }

        var manager = _configurations.GetOrAdd(issuer, key => new ConfigurationManager<OpenIdConnectConfiguration>(
            new Uri(new Uri(key.AbsoluteUri.TrimEnd('/') + "/"), ".well-known/openid-configuration").AbsoluteUri,
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(http.CreateClient(HttpClientName)) { RequireHttps = true }));

        OpenIdConnectConfiguration configuration;
        try
        {
            configuration = await manager.GetConfigurationAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidOperationException exception)
        {
            throw new HttpRequestException($"The discovery document of {issuer} could not be read.", exception);
        }

        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            ValidIssuers = [issuer.AbsoluteUri, issuer.AbsoluteUri.TrimEnd('/')],
            ValidAudience = audience,
            IssuerSigningKeys = configuration.SigningKeys,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ClockSkew = TimeSpan.FromMinutes(1),
            LifetimeValidator = (notBefore, expires, _, parameters) =>
                expires is { } end && end > time.GetUtcNow().UtcDateTime - parameters.ClockSkew
                && (notBefore is not { } start || start <= time.GetUtcNow().UtcDateTime + parameters.ClockSkew),
        }).ConfigureAwait(false);

        if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt || string.IsNullOrEmpty(jwt.Subject))
        {
            // Keys may have rotated: refresh them for the next attempt.
            manager.RequestRefresh();
            return null;
        }

        return new ExternalToken(issuer, jwt.Subject, [.. jwt.Audiences]);
    }
}

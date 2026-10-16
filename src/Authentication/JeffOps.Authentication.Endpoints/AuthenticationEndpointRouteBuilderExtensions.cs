using JeffOps.Authentication.Application;
using JeffOps.Authentication.Endpoints.Features.Accounts;
using JeffOps.Authentication.Endpoints.Features.Federation;
using JeffOps.Authentication.Endpoints.Features.PersonalAccessTokens;
using JeffOps.Authentication.Endpoints.Protocol;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Endpoints;

/// <summary>Maps the token server's HTTP endpoints.</summary>
public static class AuthenticationEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps the token server's endpoints: OpenID Connect (<c>connect/authorize</c>, <c>connect/token</c>,
    /// <c>connect/userinfo</c>, <c>connect/endsession</c>; discovery, JWKS, revocation and introspection are served by
    /// OpenIddict), the caller's personal access tokens (<c>account/pats</c>), account administration
    /// (<c>admin/accounts</c>), the service account directory (<c>directory/accounts</c>), and external sign-in
    /// (<c>account/login/discover</c>, <c>signin/{provider}</c>, <c>signin/callback/{provider}</c>).
    /// </summary>
    public static IEndpointRouteBuilder MapJeffOpsAuthentication(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<TokenServerOptions>>().Value;

        ProtocolEndpoints.Map(endpoints);
        PersonalAccessTokenEndpoints.Map(endpoints);
        AccountEndpoints.Map(endpoints, options);
        FederationEndpoints.Map(endpoints);
        return endpoints;
    }
}

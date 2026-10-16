using JeffOps.Authorization.Endpoints.Features;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

namespace JeffOps.Authorization.Endpoints;

/// <summary>Maps the authorization management endpoints.</summary>
public static class AuthorizationEndpointRouteBuilderExtensions
{
    /// <summary>
    /// Maps authorization management (docs/DESIGN.md §11.5): the read API resource services cache from
    /// (<c>authorization/*</c>, for services granted the read permission), permission self-registration, and the
    /// administration API (<c>authorization/admin/*</c>). Every route needs an authenticated caller of
    /// <paramref name="authenticationScheme"/> (the default scheme when null); the use cases check permissions against the
    /// store, and changes need a stepped-up, non-impersonation session.
    /// </summary>
    public static RouteGroupBuilder MapJeffOpsAuthorization(this IEndpointRouteBuilder endpoints, string? authenticationScheme = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var policy = new AuthorizationPolicyBuilder();
        if (authenticationScheme is not null)
        {
            policy.AddAuthenticationSchemes(authenticationScheme);
        }

        var root = endpoints.MapGroup(string.Empty).RequireAuthorization(policy.RequireAuthenticatedUser().Build());
        ReadApiEndpoints.Map(root);
        RoleEndpoints.Map(root);
        AssignmentEndpoints.Map(root);
        CatalogEndpoints.Map(root);
        return root;
    }
}

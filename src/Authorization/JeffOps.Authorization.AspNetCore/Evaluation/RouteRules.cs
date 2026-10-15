using JeffOps.Authorization.Domain.Ceilings;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authorization.AspNetCore.Evaluation;

/// <summary>
/// Endpoint metadata refusing every permission checked on one route to an impersonation token, for a route that hands out
/// or withdraws access, or changes where tenant data is delivered, under a permission whose other routes don't.
/// </summary>
public sealed class ImpersonationRouteRule
{
    private ImpersonationRouteRule()
    {
    }

    public static ImpersonationRouteRule Refuse { get; } = new();
}

/// <summary>Per-route authorization rules for minimal API endpoints (docs/DESIGN.md §11.3).</summary>
public static class AuthorizationEndpointConventionBuilderExtensions
{
    /// <summary>
    /// Requires <paramref name="permission"/>, checked at <paramref name="scopeKey"/> (default: the configured default scope).
    /// With <paramref name="instanceRouteValue"/>, the scope instance is read from that route value, so instance-bound role
    /// assignments apply (docs/DESIGN.md §17, I2).
    /// </summary>
    public static TBuilder RequirePermission<TBuilder>(this TBuilder builder, string permission, string? scopeKey = null, string? instanceRouteValue = null)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(permission);
        return builder.RequireAuthorization(PermissionPolicyProvider.Build(new PermissionRequirement(permission, scopeKey, instanceRouteValue)));
    }

    /// <summary>Requires step-up on this route for <paramref name="permissions"/>, or for every permission it checks when none are named.</summary>
    public static TBuilder RequireStepUp<TBuilder>(this TBuilder builder, params string[] permissions)
        where TBuilder : IEndpointConventionBuilder =>
        builder.WithMetadata(StepUpRouteRule.Require(permissions));

    /// <summary>
    /// Lifts step-up on this route for the named sensitive permissions. Validated at host start: naming a permission that
    /// isn't sensitive fails startup.
    /// </summary>
    public static TBuilder AllowWithoutStepUp<TBuilder>(this TBuilder builder, string permission, params string[] morePermissions)
        where TBuilder : IEndpointConventionBuilder =>
        builder.WithMetadata(StepUpRouteRule.Exempt([permission, .. morePermissions]));

    /// <summary>Refuses every permission checked on this route to an impersonation token.</summary>
    public static TBuilder RefuseUnderImpersonation<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder =>
        builder.WithMetadata(ImpersonationRouteRule.Refuse);
}

/// <summary>Reads route rules from the endpoint behind an authorization resource.</summary>
internal static class EndpointRules
{
    public static Endpoint? EndpointOf(object? resource) => resource switch
    {
        HttpContext http => http.GetEndpoint(),
        Endpoint endpoint => endpoint,
        _ => null,
    };

    public static IReadOnlyList<StepUpRouteRule> StepUpRulesOf(Endpoint? endpoint) =>
        endpoint?.Metadata.GetOrderedMetadata<StepUpRouteRule>() ?? [];

    public static bool RefusesImpersonation(Endpoint? endpoint) =>
        endpoint?.Metadata.GetMetadata<ImpersonationRouteRule>() is not null;

    /// <summary>GET or HEAD. False without a request to judge: fail closed.</summary>
    public static bool IsReadOnly(HttpContext? http) =>
        http is not null && (HttpMethods.IsGet(http.Request.Method) || HttpMethods.IsHead(http.Request.Method));
}

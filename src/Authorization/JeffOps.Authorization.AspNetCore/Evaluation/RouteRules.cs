using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authorization.Domain.Ceilings;
using JeffOps.Authorization.Domain.Decisions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authorization.AspNetCore.Evaluation;

/// <summary>
/// Endpoint metadata refusing one route to an impersonation token, for a route that hands out or withdraws access, or
/// changes where tenant data is delivered, under a permission whose other routes don't.
/// </summary>
public sealed class ImpersonationRouteRule
{
    private ImpersonationRouteRule()
    {
    }

    /// <summary>The rule's single instance, added as endpoint metadata by <c>RefuseUnderImpersonation()</c>.</summary>
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

    /// <summary>
    /// Requires step-up on this route for <paramref name="permissions"/>, or for every permission it checks when none are named.
    /// With none named, a route that checks no permission requires step-up of every interactive user.
    /// </summary>
    public static TBuilder RequireStepUp<TBuilder>(this TBuilder builder, params string[] permissions)
        where TBuilder : IEndpointConventionBuilder =>
        builder.WithMetadata(StepUpRouteRule.Require(permissions)).RequireAuthorization(RouteRuleRequirement.Policy);

    /// <summary>
    /// Lifts step-up on this route for the named sensitive permissions. Validated at host start: naming a permission that
    /// isn't sensitive fails startup.
    /// </summary>
    public static TBuilder AllowWithoutStepUp<TBuilder>(this TBuilder builder, string permission, params string[] morePermissions)
        where TBuilder : IEndpointConventionBuilder =>
        builder.WithMetadata(StepUpRouteRule.Exempt([permission, .. morePermissions]));

    /// <summary>Refuses this route to an impersonation token, whether or not the route checks a permission.</summary>
    public static TBuilder RefuseUnderImpersonation<TBuilder>(this TBuilder builder)
        where TBuilder : IEndpointConventionBuilder =>
        builder.WithMetadata(ImpersonationRouteRule.Refuse).RequireAuthorization(RouteRuleRequirement.Policy);
}

/// <summary>
/// Applies the route rules (<c>RefuseUnderImpersonation()</c>, <c>RequireStepUp()</c>) on a route that checks no permission,
/// so they never silently do nothing. A route that checks a permission applies them in the permission decision instead.
/// </summary>
public sealed class RouteRuleRequirement : IAuthorizationRequirement
{
    private RouteRuleRequirement()
    {
    }

    /// <summary>The requirement's single instance.</summary>
    public static RouteRuleRequirement Instance { get; } = new();

    /// <summary>A policy with only this requirement: it adds no authentication requirement of its own.</summary>
    public static AuthorizationPolicy Policy { get; } = new AuthorizationPolicyBuilder().AddRequirements(Instance).Build();
}

/// <summary>Decides a <see cref="RouteRuleRequirement"/>, recording a refusal's code as for a permission refusal.</summary>
internal sealed class RouteRuleAuthorizationHandler(ClaimNames names) : AuthorizationHandler<RouteRuleRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RouteRuleRequirement requirement)
    {
        var user = context.User;
        if (context.Requirements.OfType<PermissionRequirement>().Any() || user.Identity?.IsAuthenticated != true)
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        var endpoint = EndpointRules.EndpointOf(context.Resource);
        if (AccessContextReader.IsImpersonation(user, names) && EndpointRules.RefusesImpersonation(endpoint))
        {
            context.Fail(new AuthorizationFailureReason(this, AuthorizationCodes.ImpersonationNotAllowed));
        }
        else if (AccessContextReader.IsInteractiveUser(user, names)
            && !AccessContextReader.IsSteppedUp(user, names)
            && EndpointRules.StepUpRulesOf(endpoint).Any(rule => rule.Required && rule.Permissions.Count == 0))
        {
            context.Fail(new AuthorizationFailureReason(this, AuthorizationCodes.StepUpRequired));
        }
        else
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
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

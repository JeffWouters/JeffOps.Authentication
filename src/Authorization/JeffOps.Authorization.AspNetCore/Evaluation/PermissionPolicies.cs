using System.Collections.Concurrent;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authorization.Domain.Decisions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace JeffOps.Authorization.AspNetCore.Evaluation;

/// <summary>
/// Requires a permission. <see cref="ScopeKey"/> and <see cref="InstanceRouteValue"/> make the check scope-aware.
/// </summary>
public sealed class PermissionRequirement(string permission, string? scopeKey = null, string? instanceRouteValue = null) : IAuthorizationRequirement
{
    public string Permission { get; } = permission;

    public string? ScopeKey { get; } = scopeKey;

    /// <summary>Name of the route value holding the targeted scope instance id.</summary>
    public string? InstanceRouteValue { get; } = instanceRouteValue;
}

/// <summary>
/// Turns any dotted policy name (a permission code) into a <see cref="PermissionRequirement"/> on the fly, so
/// <c>RequireAuthorization("billing.invoice.read")</c> and <c>[Authorize("billing.invoice.read")]</c> work without
/// registering each policy. Other names fall through to the default provider.
/// </summary>
public sealed class PermissionPolicyProvider(IOptions<AuthorizationOptions> options) : IAuthorizationPolicyProvider
{
    private readonly DefaultAuthorizationPolicyProvider _fallback = new(options);
    private readonly ConcurrentDictionary<string, AuthorizationPolicy> _policies = new(StringComparer.Ordinal);

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => _fallback.GetDefaultPolicyAsync();

    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => _fallback.GetFallbackPolicyAsync();

    public async Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        // An explicitly registered policy wins over the permission convention.
        if (await _fallback.GetPolicyAsync(policyName).ConfigureAwait(false) is { } registered)
        {
            return registered;
        }

        return IsPermissionPolicy(policyName)
            ? _policies.GetOrAdd(policyName, static name => Build(new PermissionRequirement(name)))
            : null;
    }

    public static bool IsPermissionPolicy(string policyName) => policyName.Contains('.', StringComparison.Ordinal);

    internal static AuthorizationPolicy Build(PermissionRequirement requirement) =>
        new AuthorizationPolicyBuilder().RequireAuthenticatedUser().AddRequirements(requirement).Build();
}

/// <summary>
/// Decides a <see cref="PermissionRequirement"/> locally. A refusal records its <see cref="AuthorizationDecision.Code"/>
/// as the failure reason, so <see cref="PermissionResultHandler"/> can answer step-up and impersonation refusals precisely.
/// </summary>
internal sealed class PermissionAuthorizationHandler(
    AuthorizationEvaluator evaluator,
    IAccessContextAccessor accessContext) : AuthorizationHandler<PermissionRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true)
        {
            return;
        }

        var http = context.Resource as HttpContext;
        var request = new AuthorizationRequest(requirement.Permission)
        {
            ScopeKey = requirement.ScopeKey,
            ScopeInstanceId = InstanceOf(http, requirement.InstanceRouteValue),
        };

        var decision = await evaluator.EvaluateAsync(
            context.User,
            accessContext.GetAccessContext(),
            http,
            EndpointRules.EndpointOf(context.Resource),
            request,
            http?.RequestAborted ?? CancellationToken.None).ConfigureAwait(false);

        if (decision.Allowed)
        {
            context.Succeed(requirement);
        }
        else
        {
            context.Fail(new AuthorizationFailureReason(this, decision.Code));
        }
    }

    /// <summary>The instance id from the named route value; null (no instance-bound grant matches) when absent or not a GUID.</summary>
    private static Guid? InstanceOf(HttpContext? http, string? routeValue) =>
        routeValue is not null && Guid.TryParse(http?.GetRouteValue(routeValue)?.ToString(), out var instance) ? instance : null;
}

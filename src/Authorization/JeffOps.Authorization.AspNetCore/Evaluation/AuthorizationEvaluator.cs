using System.Security.Claims;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authorization.AspNetCore.Data;
using JeffOps.Authorization.Domain.Assignments;
using JeffOps.Authorization.Domain.Decisions;
using JeffOps.Authorization.Domain.Permissions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace JeffOps.Authorization.AspNetCore.Evaluation;

/// <summary>
/// Gathers the facts of one request — claims, route rules, cached role and policy data — and runs the
/// <see cref="AuthorizationPipeline"/>. The single evaluation path behind both the endpoint policy handler and
/// <see cref="IAuthorizer"/>, so they can't disagree.
/// </summary>
internal sealed class AuthorizationEvaluator(
    IAuthorizationData data,
    AuthorizationPipeline pipeline,
    ClaimNames names,
    IOptions<PermissionAuthorizationOptions> options,
    TimeProvider time)
{
    private static readonly IReadOnlyDictionary<string, JsonElement> NoAttributes = new Dictionary<string, JsonElement>();
    private static readonly JsonElement Null = JsonSerializer.SerializeToElement<string?>(null);

    public async Task<AuthorizationDecision> EvaluateAsync(
        ClaimsPrincipal user,
        AccessContext access,
        HttpContext? http,
        Endpoint? endpoint,
        AuthorizationRequest request,
        CancellationToken cancellationToken)
    {
        var action = Permission.Normalize(request.Action);
        var now = time.GetUtcNow();

        var hasRoleGrant = false;
        if (!access.IsRoot && access.UserId is { } userId && access.EffectiveTenantId is { } tenantId)
        {
            var assignments = await data.GetAssignmentsAsync(userId, tenantId, cancellationToken).ConfigureAwait(false);
            if (assignments.Count > 0)
            {
                var roles = await data.GetRolePermissionsAsync(cancellationToken).ConfigureAwait(false);
                var scopes = await data.GetScopesAsync(cancellationToken).ConfigureAwait(false);
                hasRoleGrant = RoleBasedAccess.Grants(
                    assignments, roles, scopes, action,
                    request.ScopeKey ?? options.Value.DefaultScopeKey,
                    request.ScopeInstanceId,
                    now);
            }
        }

        // Only attribute policies read the attribute context: without any, it isn't built (ten JSON values a decision).
        var policies = await data.GetPoliciesAsync(cancellationToken).ConfigureAwait(false);
        var facts = new AuthorizationFacts
        {
            Action = action,
            ResourceType = request.ResourceType,
            Attributes = policies.Count > 0 ? BuildAttributes(user, action, request.Resource, now) : NoAttributes,
            IsRoot = access.IsRoot,
            HasRoleGrant = hasRoleGrant,
            ServicePermissions = access.IsRoot ? [] : AccessContextReader.ValuesOf(user, names.ServicePermission),
            Policies = policies,
            PatCeiling = AccessContextReader.ValuesOf(user, names.PatCeiling),
            DelegationScopes = AccessContextReader.ValuesOf(user, names.DelegationScope),
            IsImpersonation = AccessContextReader.IsImpersonation(user, names),
            RouteRefusesImpersonation = EndpointRules.RefusesImpersonation(endpoint),
            IsReadOnlyRequest = EndpointRules.IsReadOnly(http),
            IsInteractiveUser = AccessContextReader.IsInteractiveUser(user, names),
            StepUpSatisfied = AccessContextReader.IsSteppedUp(user, names),
            StepUpRules = EndpointRules.StepUpRulesOf(endpoint),
        };

        return pipeline.Evaluate(facts);
    }

    /// <summary>
    /// The ABAC attribute context: the caller's identity claims as <c>subject.*</c>, the action, the time as
    /// <c>environment.*</c>, and the caller-supplied resource attributes as <c>resource.*</c>.
    /// </summary>
    private Dictionary<string, JsonElement> BuildAttributes(ClaimsPrincipal user, string action, IReadOnlyDictionary<string, JsonElement>? resource, DateTimeOffset now)
    {
        var context = new Dictionary<string, JsonElement>(StringComparer.Ordinal)
        {
            ["subject.sub"] = Text(user.FindFirst(names.Subject)?.Value),
            ["subject.tid"] = Text(user.FindFirst(names.Tenant)?.Value),
            ["subject.org"] = Text(user.FindFirst(names.Organization)?.Value),
            ["subject.lvl"] = Text(user.FindFirst(names.Level)?.Value),
            ["subject.act_tid"] = Text(user.FindFirst(names.ActingTenant)?.Value),
            ["subject.email"] = Text(user.FindFirst(names.Email)?.Value),
            ["subject.amr"] = JsonSerializer.SerializeToElement(AccessContextReader.ValuesOf(user, names.AuthenticationMethods)),
            ["action"] = Text(action),
            ["environment.utcHour"] = JsonSerializer.SerializeToElement(now.UtcDateTime.Hour),
            ["environment.utcDayOfWeek"] = Text(now.UtcDateTime.DayOfWeek.ToString()),
        };

        if (resource is not null)
        {
            foreach (var (key, value) in resource)
            {
                context[$"resource.{key}"] = value;
            }
        }

        return context;
    }

    private static JsonElement Text(string? value) => value is null ? Null : JsonSerializer.SerializeToElement(value);
}

/// <summary>The <see cref="IAuthorizer"/> for the current HTTP request.</summary>
internal sealed class Authorizer(
    AuthorizationEvaluator evaluator,
    IAccessContextAccessor accessContext,
    IHttpContextAccessor httpContextAccessor) : IAuthorizer
{
    public Task<AuthorizationDecision> AuthorizeAsync(AuthorizationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var http = httpContextAccessor.HttpContext;
        var user = http?.User ?? new ClaimsPrincipal(new ClaimsIdentity());
        if (user.Identity?.IsAuthenticated != true)
        {
            return Task.FromResult(AuthorizationDecision.Deny(AuthorizationCodes.NoGrant, "The caller is not authenticated."));
        }

        return evaluator.EvaluateAsync(user, accessContext.GetAccessContext(), http, http?.GetEndpoint(), request, cancellationToken);
    }

    public async Task<bool> HasPermissionAsync(string permission, CancellationToken cancellationToken = default) =>
        (await AuthorizeAsync(new AuthorizationRequest(permission), cancellationToken).ConfigureAwait(false)).Allowed;
}

/// <summary>The default <see cref="IAccessContextAccessor"/>: claims of the current request, read with <see cref="ClaimNames"/>.</summary>
internal sealed class ClaimsAccessContextAccessor(IHttpContextAccessor httpContextAccessor, ClaimNames names) : IAccessContextAccessor
{
    public AccessContext GetAccessContext() => AccessContextReader.Read(httpContextAccessor.HttpContext?.User, names);
}

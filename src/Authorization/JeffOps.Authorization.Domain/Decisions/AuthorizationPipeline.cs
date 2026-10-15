using System.Text.Json;
using JeffOps.Authorization.Domain.Ceilings;
using JeffOps.Authorization.Domain.Permissions;
using JeffOps.Authorization.Domain.Policies;

namespace JeffOps.Authorization.Domain.Decisions;

/// <summary>Stable reason codes of an <see cref="AuthorizationDecision"/>; clients may switch on them.</summary>
public static class AuthorizationCodes
{
    public const string AllowedAsRoot = "allowed_root";
    public const string AllowedByRole = "allowed_role";
    public const string AllowedByServiceGrant = "allowed_service_grant";
    public const string AllowedByPolicy = "allowed_policy";
    public const string DeniedByPolicy = "denied_by_policy";
    public const string NoGrant = "no_grant";
    public const string OutsidePatCeiling = "outside_pat_ceiling";
    public const string OutsideDelegationScope = "outside_delegation_scope";
    public const string ImpersonationNotAllowed = "impersonation_not_allowed";
    public const string StepUpRequired = "step_up_required";
}

/// <summary>The outcome of an authorization decision, with a stable <see cref="Code"/> and the per-policy trace.</summary>
public sealed record AuthorizationDecision(bool Allowed, string Code, string Reason, IReadOnlyList<PolicyTrace> Trace)
{
    public static AuthorizationDecision Deny(string code, string reason, IReadOnlyList<PolicyTrace>? trace = null) =>
        new(false, code, reason, trace ?? []);
}

/// <summary>
/// Everything known about one authorization request. Gathered by the caller (the ASP.NET Core adapter reads claims, route
/// metadata and the cached role data); evaluated purely by <see cref="AuthorizationPipeline"/>.
/// </summary>
public sealed record AuthorizationFacts
{
    public required string Action { get; init; }

    /// <summary>The type of the resource acted on, matched against <see cref="AttributePolicy.TargetResourceType"/>.</summary>
    public string? ResourceType { get; init; }

    /// <summary>The ABAC attribute context: <c>subject.*</c>, <c>resource.*</c>, <c>environment.*</c>, <c>action</c>.</summary>
    public IReadOnlyDictionary<string, JsonElement> Attributes { get; init; } = new Dictionary<string, JsonElement>();

    public bool IsRoot { get; init; }

    /// <summary>Whether the subject's role assignments grant the action at the requested scope.</summary>
    public bool HasRoleGrant { get; init; }

    /// <summary>The permissions a service principal's token carries; empty for users.</summary>
    public IReadOnlyCollection<string> ServicePermissions { get; init; } = [];

    public IReadOnlyList<AttributePolicy> Policies { get; init; } = [];

    public IReadOnlyCollection<string> PatCeiling { get; init; } = [];

    public IReadOnlyCollection<string> DelegationScopes { get; init; } = [];

    public bool IsImpersonation { get; init; }

    public bool RouteRefusesImpersonation { get; init; }

    public bool IsReadOnlyRequest { get; init; }

    /// <summary>An interactive user, as opposed to a service principal. Only interactive users are asked for step-up.</summary>
    public bool IsInteractiveUser { get; init; }

    public bool StepUpSatisfied { get; init; }

    public IReadOnlyCollection<StepUpRouteRule> StepUpRules { get; init; } = [];
}

/// <summary>
/// The single authorization decision procedure (docs/DESIGN.md §11.2). The order is part of the contract:
/// <list type="number">
/// <item>Any applicable, matching Deny policy denies — even Root.</item>
/// <item>Root, a role grant, a service-principal grant or a matching Permit policy allows; otherwise deny.</item>
/// <item>The PAT ceiling narrows.</item>
/// <item>The delegation ceiling narrows.</item>
/// <item>Impersonation limits narrow.</item>
/// <item>Step-up narrows.</item>
/// </list>
/// Steps 3–6 only take access away. Because they run after the grant, a caller without the permission is told so, rather
/// than being asked to step up for something they couldn't do anyway.
/// </summary>
public sealed class AuthorizationPipeline(StepUpPolicy stepUp, ImpersonationPolicy impersonation, DelegationCeiling delegation)
{
    public AuthorizationDecision Evaluate(AuthorizationFacts facts)
    {
        ArgumentNullException.ThrowIfNull(facts);

        var action = Permission.Normalize(facts.Action);
        var applicable = facts.Policies
            .Where(policy => policy.AppliesTo(action, facts.ResourceType))
            .OrderByDescending(policy => policy.Priority)
            .ToList();

        var trace = new List<PolicyTrace>(applicable.Count);
        var denied = false;
        var permitted = false;
        foreach (var policy in applicable)
        {
            var matched = policy.Matches(facts.Attributes);
            trace.Add(new PolicyTrace(policy.Name, policy.Effect, matched));
            denied |= matched && policy.Effect == PolicyEffect.Deny;
            permitted |= matched && policy.Effect == PolicyEffect.Permit;
        }

        if (denied)
        {
            return AuthorizationDecision.Deny(AuthorizationCodes.DeniedByPolicy, "Denied by an attribute policy (deny overrides).", trace);
        }

        var granted = Grant(facts, action, permitted);
        if (granted is null)
        {
            return AuthorizationDecision.Deny(AuthorizationCodes.NoGrant, "No role, service grant or policy permits this action.", trace);
        }

        if (!PatCeiling.Allows(facts.PatCeiling, action))
        {
            return AuthorizationDecision.Deny(AuthorizationCodes.OutsidePatCeiling, "Outside the access token's permission ceiling.", trace);
        }

        if (!delegation.Allows(facts.DelegationScopes, action))
        {
            return AuthorizationDecision.Deny(AuthorizationCodes.OutsideDelegationScope, "Outside the scope of the delegation this session acts under.", trace);
        }

        if (!impersonation.Allows(facts.IsImpersonation, action, facts.RouteRefusesImpersonation, facts.IsReadOnlyRequest))
        {
            return AuthorizationDecision.Deny(AuthorizationCodes.ImpersonationNotAllowed, "Not available while impersonating another user.", trace);
        }

        if (!stepUp.Allows(action, facts.StepUpRules, facts.IsInteractiveUser, facts.StepUpSatisfied))
        {
            return AuthorizationDecision.Deny(AuthorizationCodes.StepUpRequired, "This action requires a multi-factor sign-in (step-up).", trace);
        }

        return granted with { Trace = trace };
    }

    private static AuthorizationDecision? Grant(AuthorizationFacts facts, string action, bool permitted)
    {
        if (facts.IsRoot)
        {
            return new AuthorizationDecision(true, AuthorizationCodes.AllowedAsRoot, "Allowed (root).", []);
        }

        if (facts.HasRoleGrant)
        {
            return new AuthorizationDecision(true, AuthorizationCodes.AllowedByRole, "Allowed by a role grant.", []);
        }

        if (Permission.GrantsAny(facts.ServicePermissions, action))
        {
            return new AuthorizationDecision(true, AuthorizationCodes.AllowedByServiceGrant, "Allowed by a service-principal grant.", []);
        }

        return permitted
            ? new AuthorizationDecision(true, AuthorizationCodes.AllowedByPolicy, "Allowed by an attribute policy.", [])
            : null;
    }
}

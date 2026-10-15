using System.Text.Json;
using JeffOps.Authorization.Domain.Ceilings;
using JeffOps.Authorization.Domain.Decisions;
using JeffOps.Authorization.Domain.Policies;

namespace JeffOps.Authorization.Domain.Tests;

public sealed class AuthorizationPipelineTests
{
    private const string Action = "billing.invoice.read";

    private static readonly AuthorizationPipeline Pipeline = new(
        new StepUpPolicy(["policy.write"]),
        new ImpersonationPolicy(["roles.assignments.write"]),
        DelegationCeiling.Default);

    private static AttributePolicy Policy(
        PolicyEffect effect,
        string condition = """{"true":true}""",
        string action = Action,
        string? resourceType = null,
        bool enabled = true,
        int priority = 0) =>
        AttributePolicy.Compile($"{effect}:{condition}", effect, action, resourceType, condition, priority, enabled);

    private static Dictionary<string, JsonElement> Context(params (string Key, object? Value)[] pairs) =>
        pairs.ToDictionary(pair => pair.Key, pair => JsonSerializer.SerializeToElement(pair.Value));

    private static AuthorizationFacts Facts(string action = Action) => new() { Action = action, IsInteractiveUser = true };

    [Fact]
    public void Default_deny_without_grant_or_policy() =>
        Pipeline.Evaluate(Facts()).ShouldSatisfyAllConditions(
            decision => decision.Allowed.ShouldBeFalse(),
            decision => decision.Code.ShouldBe(AuthorizationCodes.NoGrant));

    [Fact]
    public void A_role_grant_allows() =>
        Pipeline.Evaluate(Facts() with { HasRoleGrant = true }).Code.ShouldBe(AuthorizationCodes.AllowedByRole);

    [Fact]
    public void A_service_grant_allows_with_prefix_matching() =>
        Pipeline.Evaluate(Facts() with { ServicePermissions = ["billing.*"] }).Code.ShouldBe(AuthorizationCodes.AllowedByServiceGrant);

    [Fact]
    public void A_permit_policy_grants_beyond_roles() =>
        Pipeline.Evaluate(Facts() with { Policies = [Policy(PolicyEffect.Permit)] }).Code.ShouldBe(AuthorizationCodes.AllowedByPolicy);

    [Fact]
    public void A_deny_policy_overrides_a_role_grant()
    {
        var facts = Facts() with
        {
            HasRoleGrant = true,
            Policies = [Policy(PolicyEffect.Deny, """{"ne":["resource.tenantId","subject.tid"]}""")],
            Attributes = Context(("resource.tenantId", "t-2"), ("subject.tid", "t-1")),
        };

        Pipeline.Evaluate(facts).Code.ShouldBe(AuthorizationCodes.DeniedByPolicy);
    }

    [Fact]
    public void A_deny_policy_overrides_root() =>
        Pipeline.Evaluate(Facts() with { IsRoot = true, Policies = [Policy(PolicyEffect.Deny)] }).Allowed.ShouldBeFalse();

    [Fact]
    public void Root_is_allowed_without_a_matching_deny() =>
        Pipeline.Evaluate(Facts() with { IsRoot = true }).Code.ShouldBe(AuthorizationCodes.AllowedAsRoot);

    [Fact]
    public void An_unmatched_deny_does_not_apply_and_is_traced()
    {
        var facts = Facts() with
        {
            HasRoleGrant = true,
            Policies = [Policy(PolicyEffect.Deny, """{"ne":["resource.tenantId","subject.tid"]}""")],
            Attributes = Context(("resource.tenantId", "t-1"), ("subject.tid", "t-1")),
        };

        var decision = Pipeline.Evaluate(facts);

        decision.Allowed.ShouldBeTrue();
        decision.Trace.ShouldContain(trace => trace.Effect == PolicyEffect.Deny && !trace.Matched);
    }

    [Fact]
    public void Disabled_and_non_targeting_policies_are_ignored()
    {
        var facts = Facts() with
        {
            HasRoleGrant = true,
            Policies = [Policy(PolicyEffect.Deny, enabled: false), Policy(PolicyEffect.Deny, action: "other.action")],
        };

        var decision = Pipeline.Evaluate(facts);

        decision.Allowed.ShouldBeTrue();
        decision.Trace.ShouldBeEmpty();
    }

    [Fact]
    public void A_wildcard_target_applies_to_any_action() =>
        Pipeline.Evaluate(Facts("anything.at.all") with { IsRoot = true, Policies = [Policy(PolicyEffect.Deny, action: "*")] })
            .Allowed.ShouldBeFalse();

    [Fact]
    public void A_policy_limited_to_a_resource_type_applies_only_to_that_type()
    {
        AttributePolicy[] policies = [Policy(PolicyEffect.Deny, resourceType: "invoice")];

        Pipeline.Evaluate(Facts() with { HasRoleGrant = true, Policies = policies, ResourceType = "invoice" }).Allowed.ShouldBeFalse();
        Pipeline.Evaluate(Facts() with { HasRoleGrant = true, Policies = policies, ResourceType = "INVOICE" }).Allowed.ShouldBeFalse();
        Pipeline.Evaluate(Facts() with { HasRoleGrant = true, Policies = policies, ResourceType = "subscription" }).Allowed.ShouldBeTrue();
        Pipeline.Evaluate(Facts() with { HasRoleGrant = true, Policies = policies }).Allowed.ShouldBeTrue();
    }

    [Fact]
    public void A_policy_whose_condition_does_not_compile_fails_closed()
    {
        var brokenDeny = AttributePolicy.Compile("deny", PolicyEffect.Deny, Action, null, "{\"bogus\":1}", 0, enabled: true);
        var brokenPermit = AttributePolicy.Compile("permit", PolicyEffect.Permit, Action, null, "{\"bogus\":1}", 0, enabled: true);

        brokenDeny.CompileError.ShouldNotBeNull();
        Pipeline.Evaluate(Facts() with { HasRoleGrant = true, Policies = [brokenDeny] }).Allowed.ShouldBeFalse("a broken Deny still denies");
        Pipeline.Evaluate(Facts() with { Policies = [brokenPermit] }).Allowed.ShouldBeFalse("a broken Permit never permits");
    }

    [Fact]
    public void The_pat_ceiling_narrows_even_root()
    {
        Pipeline.Evaluate(Facts() with { IsRoot = true, PatCeiling = ["mail.*"] }).Code.ShouldBe(AuthorizationCodes.OutsidePatCeiling);
        Pipeline.Evaluate(Facts() with { IsRoot = true, PatCeiling = ["billing.*"] }).Allowed.ShouldBeTrue();
    }

    [Fact]
    public void A_ceiling_never_grants() =>
        Pipeline.Evaluate(Facts() with { PatCeiling = ["*"], DelegationScopes = ["admin"] }).Code.ShouldBe(AuthorizationCodes.NoGrant);

    [Fact]
    public void The_delegation_ceiling_narrows()
    {
        Pipeline.Evaluate(Facts("billing.invoice.write") with { HasRoleGrant = true, DelegationScopes = ["readonly"] })
            .Code.ShouldBe(AuthorizationCodes.OutsideDelegationScope);
        Pipeline.Evaluate(Facts() with { HasRoleGrant = true, DelegationScopes = ["readonly"] }).Allowed.ShouldBeTrue();
    }

    [Fact]
    public void Impersonation_limits_narrow_writes_of_refused_permissions()
    {
        var facts = Facts("roles.assignments.write") with { HasRoleGrant = true, IsImpersonation = true };

        Pipeline.Evaluate(facts).Code.ShouldBe(AuthorizationCodes.ImpersonationNotAllowed);
        Pipeline.Evaluate(facts with { IsReadOnlyRequest = true }).Allowed.ShouldBeTrue();
        Pipeline.Evaluate(facts with { IsImpersonation = false }).Allowed.ShouldBeTrue();
    }

    [Fact]
    public void Step_up_narrows_sensitive_actions_for_interactive_users()
    {
        var facts = Facts("policy.write") with { HasRoleGrant = true };

        Pipeline.Evaluate(facts).Code.ShouldBe(AuthorizationCodes.StepUpRequired);
        Pipeline.Evaluate(facts with { StepUpSatisfied = true }).Allowed.ShouldBeTrue();
        Pipeline.Evaluate(facts with { IsInteractiveUser = false }).Allowed.ShouldBeTrue();
        Pipeline.Evaluate(facts with { StepUpRules = [StepUpRouteRule.Exempt("policy.write")] }).Allowed.ShouldBeTrue();
    }

    [Fact]
    public void Step_up_binds_root_users_too() =>
        Pipeline.Evaluate(Facts("policy.write") with { IsRoot = true }).Code.ShouldBe(AuthorizationCodes.StepUpRequired);

    [Fact]
    public void A_missing_grant_is_reported_before_step_up() =>
        Pipeline.Evaluate(Facts("policy.write")).Code.ShouldBe(
            AuthorizationCodes.NoGrant,
            "a caller without the permission is told so, not asked to sign in again");

    [Fact]
    public void Impersonation_is_reported_before_step_up() =>
        Pipeline.Evaluate(Facts("roles.assignments.write") with
        {
            HasRoleGrant = true,
            IsImpersonation = true,
            StepUpRules = [StepUpRouteRule.Require()],
        }).Code.ShouldBe(AuthorizationCodes.ImpersonationNotAllowed);
}

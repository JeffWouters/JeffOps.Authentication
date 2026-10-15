using JeffOps.Authorization.Domain.Ceilings;

namespace JeffOps.Authorization.Domain.Tests;

public sealed class PatCeilingTests
{
    [Theory]
    [InlineData("mail.domain.read", true)]
    [InlineData("MAIL.DOMAIN.READ", true)]
    [InlineData("mail.domain.manage", false)]
    public void An_exact_ceiling_permits_only_that_action(string action, bool allowed) =>
        PatCeiling.Allows(["mail.domain.read"], action).ShouldBe(allowed);

    [Theory]
    [InlineData("mail.domain.read", true)]
    [InlineData("mail.analysis.read", true)]
    [InlineData("billing.invoice.read", false)]
    public void A_prefix_ceiling_permits_its_domain(string action, bool allowed) =>
        PatCeiling.Allows(["mail.*"], action).ShouldBe(allowed);

    [Fact]
    public void A_wildcard_ceiling_permits_anything() => PatCeiling.Allows(["*"], "anything.at.all").ShouldBeTrue();

    [Fact]
    public void No_ceiling_is_unrestricted() => PatCeiling.Allows([], "billing.subscription.cancel").ShouldBeTrue();

    [Fact]
    public void Several_entries_form_a_union()
    {
        string[] ceiling = ["mail.domain.read", "scan.result.read"];

        PatCeiling.Allows(ceiling, "mail.domain.read").ShouldBeTrue();
        PatCeiling.Allows(ceiling, "scan.result.read").ShouldBeTrue();
        PatCeiling.Allows(ceiling, "billing.invoice.read").ShouldBeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void An_empty_stored_ceiling_parses_to_nothing(string? stored) => PatCeiling.Parse(stored).ShouldBeEmpty();

    [Fact]
    public void A_stored_ceiling_splits_on_spaces_and_trims() =>
        PatCeiling.Parse("  mail.domain.read   scan.result.read ").ShouldBe(["mail.domain.read", "scan.result.read"]);
}

public sealed class DelegationCeilingTests
{
    private static readonly DelegationCeiling Ceiling = DelegationCeiling.Default with
    {
        VerbScopes = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["readonly"] = ["read", "verify"],
        },
        PrefixScopes = new Dictionary<string, IReadOnlyCollection<string>>(StringComparer.OrdinalIgnoreCase)
        {
            ["billing"] = ["billing."],
        },
    };

    [Theory]
    [InlineData("findings.read", true)]
    [InlineData("tenancy.membership.read", true)]
    [InlineData("SECURITY.SCAN.READ", true)]
    [InlineData("audit.log.verify", true)]
    [InlineData("security.scan.run", false)]
    [InlineData("policy.write", false)]
    [InlineData("read", false)]
    public void A_read_only_delegation_permits_reads_only(string action, bool allowed) =>
        Ceiling.Allows(["readonly"], action).ShouldBe(allowed);

    [Theory]
    [InlineData("billing.subscription.write", true)]
    [InlineData("billing.account.read", true)]
    [InlineData("findings.read", false)]
    public void A_prefix_scope_permits_its_prefix_only(string action, bool allowed) =>
        Ceiling.Allows(["billing"], action).ShouldBe(allowed);

    [Fact]
    public void Admin_and_no_scope_are_unrestricted()
    {
        Ceiling.Allows(["admin"], "remediation.execute").ShouldBeTrue();
        Ceiling.Allows(["ADMIN "], "remediation.execute").ShouldBeTrue();
        Ceiling.Allows([], "remediation.execute").ShouldBeTrue();
    }

    [Fact]
    public void Several_scopes_form_a_union_and_unknown_ones_grant_nothing()
    {
        string[] both = ["readonly", "billing"];

        Ceiling.Allows(both, "billing.subscription.write").ShouldBeTrue();
        Ceiling.Allows(both, "findings.read").ShouldBeTrue();
        Ceiling.Allows(both, "security.scan.run").ShouldBeFalse();
        Ceiling.Allows(["superuser"], "findings.read").ShouldBeFalse();
    }

    [Fact]
    public void The_default_ceiling_knows_admin_and_readonly_only()
    {
        DelegationCeiling.Default.Allows(["readonly"], "x.read").ShouldBeTrue();
        DelegationCeiling.Default.Allows(["readonly"], "audit.log.verify").ShouldBeFalse();
        DelegationCeiling.Default.Allows(["billing"], "billing.invoice.read").ShouldBeFalse();
    }
}

public sealed class StepUpPolicyTests
{
    private static readonly StepUpPolicy Policy = new(["policy.write", "remediation.execute"]);

    [Fact]
    public void A_sensitive_action_needs_a_stepped_up_interactive_user()
    {
        Policy.Allows("policy.write", [], isInteractiveUser: true, stepUpSatisfied: false).ShouldBeFalse();
        Policy.Allows("policy.write", [], isInteractiveUser: true, stepUpSatisfied: true).ShouldBeTrue();
        Policy.Allows("POLICY.WRITE", [], isInteractiveUser: true, stepUpSatisfied: false).ShouldBeFalse();
    }

    [Fact]
    public void Service_principals_are_never_asked_for_step_up() =>
        Policy.Allows("policy.write", [], isInteractiveUser: false, stepUpSatisfied: false).ShouldBeTrue();

    [Fact]
    public void Other_actions_are_unaffected() =>
        Policy.Allows("findings.read", [], isInteractiveUser: true, stepUpSatisfied: false).ShouldBeTrue();

    [Fact]
    public void An_exemption_lifts_step_up_for_the_named_permission_on_that_route_only()
    {
        StepUpRouteRule[] rules = [StepUpRouteRule.Exempt("remediation.execute")];

        Policy.IsRequired("remediation.execute", rules).ShouldBeFalse();
        Policy.IsRequired("policy.write", rules).ShouldBeTrue();
        Policy.IsRequired("remediation.execute", []).ShouldBeTrue();
    }

    [Fact]
    public void A_requirement_adds_step_up_to_a_non_sensitive_permission()
    {
        Policy.IsRequired("tenant.write", [StepUpRouteRule.Require("tenant.write")]).ShouldBeTrue();
        Policy.IsRequired("tenant.write", [StepUpRouteRule.Require()]).ShouldBeTrue("a requirement naming nothing covers every permission");
        Policy.IsRequired("tenant.read", [StepUpRouteRule.Require("tenant.write")]).ShouldBeFalse();
    }

    [Fact]
    public void A_requirement_wins_over_an_exemption()
    {
        StepUpRouteRule[] rules = [StepUpRouteRule.Exempt("policy.write"), StepUpRouteRule.Require("policy.write")];

        Policy.IsRequired("policy.write", rules).ShouldBeTrue();
    }

    [Fact]
    public void An_exemption_must_name_a_permission() =>
        Should.Throw<ArgumentException>(() => StepUpRouteRule.Exempt());
}

public sealed class ImpersonationPolicyTests
{
    private static readonly ImpersonationPolicy Policy = new(["roles.assignments.write", "webhooks.endpoint.write"]);

    [Fact]
    public void A_non_impersonation_token_is_never_limited() =>
        Policy.Allows(isImpersonation: false, "roles.assignments.write", routeRefusesImpersonation: true, isReadOnlyRequest: false).ShouldBeTrue();

    [Fact]
    public void Refused_permissions_are_refused_on_writes()
    {
        Policy.Allows(true, "roles.assignments.write", routeRefusesImpersonation: false, isReadOnlyRequest: false).ShouldBeFalse();
        Policy.Allows(true, "WEBHOOKS.ENDPOINT.WRITE", routeRefusesImpersonation: false, isReadOnlyRequest: false).ShouldBeFalse();
    }

    [Fact]
    public void Refused_permissions_stay_readable() =>
        Policy.Allows(true, "roles.assignments.write", routeRefusesImpersonation: false, isReadOnlyRequest: true).ShouldBeTrue();

    [Fact]
    public void Other_permissions_are_allowed() =>
        Policy.Allows(true, "findings.write", routeRefusesImpersonation: false, isReadOnlyRequest: false).ShouldBeTrue();

    [Fact]
    public void A_route_that_refuses_impersonation_refuses_everything_even_reads() =>
        Policy.Allows(true, "findings.read", routeRefusesImpersonation: true, isReadOnlyRequest: true).ShouldBeFalse();
}

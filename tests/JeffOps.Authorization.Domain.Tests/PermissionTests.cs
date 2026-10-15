using JeffOps.Authorization.Domain.Permissions;

namespace JeffOps.Authorization.Domain.Tests;

public sealed class PermissionTests
{
    [Theory]
    [InlineData("*", "anything.at.all", true)]
    [InlineData("billing.subscription.read", "billing.subscription.read", true)]
    [InlineData("BILLING.SUBSCRIPTION.READ", "billing.subscription.read", true)]
    [InlineData("billing.*", "billing.subscription.read", true)]
    [InlineData("billing.*", "billing.account.write", true)]
    [InlineData("billing.*", "audit.log.read", false)]
    [InlineData("audit.log.*", "audit.log.verify", true)]
    [InlineData("audit.log.*", "audit.report.read", false)]
    [InlineData("billing.subscription.read", "billing.subscription.write", false)]
    [InlineData("billing.*", "billingx.account.read", false)]
    public void Grants_matches_exact_global_and_prefix(string held, string requested, bool expected)
    {
        Permission.Grants(held, requested).ShouldBe(expected);
        PermissionSet.From([held]).Grants(requested).ShouldBe(expected, "the compiled set must agree with the reference rule");
    }

    [Fact]
    public void GrantsAny_is_true_when_any_held_permission_grants()
    {
        string[] held = ["audit.log.read", "billing.*"];

        Permission.GrantsAny(held, "billing.subscription.write").ShouldBeTrue();
        Permission.GrantsAny(held, "scopes.hierarchy.write").ShouldBeFalse();
    }

    [Fact]
    public void Compiled_set_agrees_with_the_reference_rule_on_many_combinations()
    {
        string[] held = ["audit.log.*", "billing.subscription.read", "reports.*", "x.y.z"];
        string[] requests =
        [
            "audit.log.read", "audit.log.export", "audit.report.read", "billing.subscription.read",
            "billing.subscription.write", "reports.daily.generate", "reports", "x.y.z", "x.y", "X.Y.Z", "",
        ];

        var set = PermissionSet.From(held);

        foreach (var request in requests)
        {
            set.Grants(request).ShouldBe(Permission.GrantsAny(held, request), $"request '{request}'");
        }
    }

    [Fact]
    public void Empty_set_grants_nothing()
    {
        PermissionSet.Empty.IsEmpty.ShouldBeTrue();
        PermissionSet.Empty.Grants("anything.at.all").ShouldBeFalse();
        PermissionSet.From(["", "  "]).IsEmpty.ShouldBeTrue();
    }

    [Fact]
    public void Normalize_lowercases_and_trims() => Permission.Normalize("  Billing.Invoice.READ ").ShouldBe("billing.invoice.read");
}

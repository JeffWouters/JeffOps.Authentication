using JeffOps.Authorization.Domain.Management;
using JeffOps.Authorization.Domain.Scopes;

namespace JeffOps.Authorization.Domain.Tests;

public sealed class ManagementRuleTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] Privileged = ["authorization.assignments.write"];

    private static Role RoleWith(params string[] permissions)
    {
        var role = Role.Create("Role", Guid.NewGuid(), Now);
        foreach (var permission in permissions)
        {
            role.AddPermission(permission);
        }

        return role;
    }

    [Fact]
    public void A_role_granting_a_privileged_permission_through_a_wildcard_is_privileged()
    {
        AssignmentRules.IsPrivileged(RoleWith("authorization.*"), Privileged).ShouldBeTrue();
        AssignmentRules.IsPrivileged(RoleWith("billing.invoices.read"), Privileged).ShouldBeFalse();
    }

    [Fact]
    public void Granting_a_privileged_role_needs_every_permission_it_carries()
    {
        var role = RoleWith("authorization.assignments.write", "billing.invoices.write");

        AssignmentRules.CeilingViolations(role, ["authorization.assignments.write"], grantingToSelf: false, Privileged)
            .ShouldBe(["billing.invoices.write"]);
        AssignmentRules.CeilingViolations(role, ["authorization.*", "billing.*"], grantingToSelf: false, Privileged).ShouldBeEmpty();
    }

    [Fact]
    public void Ordinary_roles_can_be_granted_to_others_but_not_self_granted_beyond_holdings()
    {
        var role = RoleWith("billing.invoices.write");

        AssignmentRules.CeilingViolations(role, [], grantingToSelf: false, Privileged).ShouldBeEmpty();
        AssignmentRules.CeilingViolations(role, [], grantingToSelf: true, Privileged).ShouldBe(["billing.invoices.write"]);
    }

    [Fact]
    public void Break_glass_must_be_time_boxed_within_the_maximum()
    {
        var role = Role.Create("Break glass", null, Now, isBreakGlass: true);
        var max = TimeSpan.FromHours(8);

        AssignmentRules.ExpiryProblem(role, null, Now, max).ShouldNotBeNull();
        AssignmentRules.ExpiryProblem(role, Now.AddHours(9), Now, max).ShouldNotBeNull();
        AssignmentRules.ExpiryProblem(role, Now.AddHours(1), Now, max).ShouldBeNull();
        AssignmentRules.ExpiryProblem(RoleWith(), Now.AddMinutes(-1), Now, max).ShouldNotBeNull();
    }

    [Fact]
    public void A_role_with_a_minimum_scope_is_assignable_there_or_broader()
    {
        var tree = new ScopeTree([
            KeyValuePair.Create("system", (string?)null),
            KeyValuePair.Create("tenant", (string?)"system"),
            KeyValuePair.Create("workspace", (string?)"tenant"),
        ]);
        var role = Role.Create("Tenant role", Guid.NewGuid(), Now, minScopeKey: "tenant");

        AssignmentRules.ScopeAllowed(role, "tenant", tree).ShouldBeTrue();
        AssignmentRules.ScopeAllowed(role, "system", tree).ShouldBeTrue();
        AssignmentRules.ScopeAllowed(role, "workspace", tree).ShouldBeFalse();
        AssignmentRules.ScopeAllowed(role, "unknown", tree).ShouldBeFalse();
    }

    [Fact]
    public void A_role_change_is_decided_once_and_never_by_its_requester()
    {
        var requester = Guid.NewGuid();
        var request = RoleChangeRequest.PermissionChange(RoleChangeKind.AddPermission, Guid.NewGuid(), "billing.invoices.read", Guid.NewGuid(), requester, Now);

        Should.Throw<InvalidOperationException>(() => request.Decide(approve: true, requester, null, Now));

        request.Decide(approve: true, Guid.NewGuid(), "ok", Now);
        request.Status.ShouldBe(RoleChangeStatus.Approved);
        Should.Throw<InvalidOperationException>(() => request.Decide(approve: false, Guid.NewGuid(), null, Now));
    }

    [Fact]
    public void Approval_defaults_to_required_and_a_tenant_setting_overrides_the_global_one()
    {
        ApprovalSetting.Effective(null, null).ShouldBeTrue();
        ApprovalSetting.Effective(null, ApprovalSetting.Create(null, false, null, Now)).ShouldBeFalse();
        ApprovalSetting.Effective(ApprovalSetting.Create(Guid.NewGuid(), true, null, Now), ApprovalSetting.Create(null, false, null, Now)).ShouldBeTrue();
    }

    [Fact]
    public void Recertification_is_bounded()
    {
        AssignmentRules.RecertifyProblem(Now.AddDays(400), Now, TimeSpan.FromDays(365)).ShouldNotBeNull();
        AssignmentRules.RecertifyProblem(Now.AddDays(-1), Now, TimeSpan.FromDays(365)).ShouldNotBeNull();
        AssignmentRules.RecertifyProblem(Now.AddDays(30), Now, TimeSpan.FromDays(365)).ShouldBeNull();
    }
}

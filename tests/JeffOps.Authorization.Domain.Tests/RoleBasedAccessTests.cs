using JeffOps.Authorization.Domain.Assignments;
using JeffOps.Authorization.Domain.Permissions;
using JeffOps.Authorization.Domain.Scopes;

namespace JeffOps.Authorization.Domain.Tests;

public sealed class RoleBasedAccessTests
{
    private static readonly Guid Reader = Guid.Parse("0f8b1d3e-0000-4000-8000-000000000001");
    private static readonly Guid Admin = Guid.Parse("0f8b1d3e-0000-4000-8000-000000000002");
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);

    private static readonly Dictionary<Guid, PermissionSet> Roles = new()
    {
        [Reader] = PermissionSet.From(["findings.read"]),
        [Admin] = PermissionSet.From(["findings.*"]),
    };

    // system → organization → tenant → workspace
    private static readonly ScopeTree Scopes = new(new Dictionary<string, string?>
    {
        ["system"] = null,
        ["organization"] = "system",
        ["tenant"] = "organization",
        ["workspace"] = "tenant",
    });

    private static bool Grants(RoleAssignment assignment, string permission, string scope = "tenant", Guid? instance = null) =>
        RoleBasedAccess.Grants([assignment], Roles, Scopes, permission, scope, instance, Now);

    [Fact]
    public void A_role_grants_its_permissions_at_its_scope() =>
        Grants(new RoleAssignment(Reader, "tenant"), "findings.read").ShouldBeTrue();

    [Fact]
    public void A_role_does_not_grant_other_permissions() =>
        Grants(new RoleAssignment(Reader, "tenant"), "findings.write").ShouldBeFalse();

    [Fact]
    public void A_wildcard_role_grants_its_prefix() =>
        Grants(new RoleAssignment(Admin, "tenant"), "findings.write").ShouldBeTrue();

    [Fact]
    public void A_grant_at_a_broader_scope_reaches_narrower_requests()
    {
        Grants(new RoleAssignment(Reader, "organization"), "findings.read", scope: "workspace").ShouldBeTrue();
        Grants(new RoleAssignment(Reader, "system"), "findings.read", scope: "tenant").ShouldBeTrue();
    }

    [Fact]
    public void A_grant_at_a_narrower_scope_does_not_reach_broader_requests() =>
        Grants(new RoleAssignment(Reader, "workspace"), "findings.read", scope: "tenant").ShouldBeFalse();

    [Fact]
    public void An_instance_bound_grant_applies_only_to_that_instance()
    {
        var workspace = Guid.NewGuid();
        var assignment = new RoleAssignment(Reader, "workspace", workspace);

        Grants(assignment, "findings.read", "workspace", workspace).ShouldBeTrue();
        Grants(assignment, "findings.read", "workspace", Guid.NewGuid()).ShouldBeFalse();
        Grants(assignment, "findings.read", "workspace").ShouldBeFalse();
    }

    [Fact]
    public void A_whole_scope_grant_applies_to_any_instance() =>
        Grants(new RoleAssignment(Reader, "workspace"), "findings.read", "workspace", Guid.NewGuid()).ShouldBeTrue();

    [Fact]
    public void An_expired_grant_does_not_apply()
    {
        Grants(new RoleAssignment(Reader, "tenant", ExpiresAt: Now), "findings.read").ShouldBeFalse("expiry is inclusive");
        Grants(new RoleAssignment(Reader, "tenant", ExpiresAt: Now.AddSeconds(1)), "findings.read").ShouldBeTrue();
    }

    [Fact]
    public void An_unknown_role_or_scope_grants_nothing()
    {
        Grants(new RoleAssignment(Guid.NewGuid(), "tenant"), "findings.read").ShouldBeFalse();
        Grants(new RoleAssignment(Reader, "galaxy"), "findings.read").ShouldBeFalse();
        Grants(new RoleAssignment(Reader, ""), "findings.read").ShouldBeFalse();
    }

    [Fact]
    public void Any_matching_assignment_grants() =>
        RoleBasedAccess.Grants(
            [new RoleAssignment(Reader, "workspace"), new RoleAssignment(Admin, "tenant")],
            Roles, Scopes, "findings.write", "tenant", null, Now).ShouldBeTrue();
}

public sealed class ScopeHierarchyTests
{
    private static readonly Dictionary<string, string?> ParentOf = new()
    {
        ["system"] = null,
        ["organization"] = "system",
        ["tenant"] = "organization",
        ["delegated"] = "organization",
    };

    [Fact]
    public void Ancestors_run_from_the_scope_to_the_root() =>
        ScopeHierarchy.AncestorsAndSelf("tenant", ParentOf).ShouldBe(["tenant", "organization", "system"]);

    [Fact]
    public void Unknown_keys_have_no_ancestors() => ScopeHierarchy.AncestorsAndSelf("nope", ParentOf).ShouldBeEmpty();

    [Fact]
    public void Siblings_do_not_contain_each_other() => ScopeHierarchy.IsWithin("tenant", "delegated", ParentOf).ShouldBeFalse();

    [Fact]
    public void A_cycle_in_stored_data_does_not_loop_forever()
    {
        var cyclic = new Dictionary<string, string?> { ["a"] = "b", ["b"] = "a" };

        ScopeHierarchy.AncestorsAndSelf("a", cyclic).ShouldBe(["a", "b"]);
    }

    [Theory]
    [InlineData("organization", "tenant", true)]
    [InlineData("organization", "organization", true)]
    [InlineData("tenant", "delegated", false)]
    [InlineData("tenant", null, false)]
    public void WouldCycle_detects_reparenting_into_the_own_subtree(string key, string? newParent, bool expected) =>
        ScopeHierarchy.WouldCycle(key, newParent, ParentOf).ShouldBe(expected);
}

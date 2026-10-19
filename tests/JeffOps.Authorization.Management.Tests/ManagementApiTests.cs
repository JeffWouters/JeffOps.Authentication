using System.Net;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authorization.Application.Features.Assignments;
using JeffOps.Authorization.Contracts;
using Microsoft.Extensions.DependencyInjection;
using static JeffOps.Authorization.Management.Tests.ManagementHost;

namespace JeffOps.Authorization.Management.Tests;

public sealed class ManagementApiTests
{
    private static readonly Guid Alice = Guid.Parse("a11ce000-0000-4000-8000-000000000001");
    private static readonly Guid Bob = Guid.Parse("b0b00000-0000-4000-8000-000000000002");
    private static readonly Guid Carol = Guid.Parse("ca201000-0000-4000-8000-000000000003");

    [Fact]
    public async Task Startup_seeds_scopes_and_built_in_roles()
    {
        await using var host = await StartAsync();

        var scopes = await host.ReadAsync<List<ScopeDto>>(await host.GetAsync(RootUser(), ManagementRoutes.Scopes));
        scopes.Select(scope => scope.Key).ShouldBe(["system", "organization", "tenant", "workspace"], ignoreOrder: true);

        var roles = await host.ReadAsync<List<RoleDto>>(await host.GetAsync(RootUser(), ManagementRoutes.Roles));
        roles.ShouldContain(role => role.Name == TenantAdmin && role.IsBuiltIn && role.Permissions.Contains("authorization.roles.write"));
        roles.ShouldContain(role => role.Name == BreakGlass && role.IsBreakGlass);
    }

    [Fact]
    public async Task Unauthenticated_callers_are_refused()
    {
        await using var host = await StartAsync();

        var response = await host.Client.GetAsync(ManagementRoutes.Roles, TestContext.Current.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task An_assigned_admin_can_read_and_the_co_hosted_decision_uses_the_store()
    {
        await using var host = await StartAsync();
        await AssignAsync(host, RootUser(), Alice, TenantAdmin);

        var assignments = await host.ReadAsync<List<AssignmentDto>>(await host.GetAsync(User(Alice), ManagementRoutes.Assignments));
        assignments.ShouldHaveSingleItem().RoleName.ShouldBe(TenantAdmin);

        (await host.GetAsync(User(Alice), "/invoices")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await host.GetAsync(User(Carol), "/invoices")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Users_without_the_permission_are_refused()
    {
        await using var host = await StartAsync();

        var response = await host.GetAsync(User(Carol), ManagementRoutes.Assignments);

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await CodeOf(response)).ShouldBe("missing_permission");
    }

    [Fact]
    public async Task Changes_need_a_stepped_up_sign_in()
    {
        await using var host = await StartAsync();
        await AssignAsync(host, RootUser(), Alice, TenantAdmin);

        var response = await host.SendAsync(User(Alice, steppedUp: false), HttpMethod.Post, ManagementRoutes.Roles, new CreateRoleRequest("Readers"));

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await CodeOf(response)).ShouldBe("step_up_required");
        response.Headers.WwwAuthenticate.ToString().ShouldContain("insufficient_user_authentication");
    }

    [Fact]
    public async Task Changes_are_refused_while_impersonating()
    {
        await using var host = await StartAsync();
        await AssignAsync(host, RootUser(), Alice, TenantAdmin);

        var response = await host.SendAsync(User(Alice, extra: ("act", "support")), HttpMethod.Post, ManagementRoutes.Roles, new CreateRoleRequest("Readers"));

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await CodeOf(response)).ShouldBe("impersonation_not_allowed");
    }

    [Fact]
    public async Task A_role_cannot_carry_permissions_its_creator_does_not_hold()
    {
        await using var host = await StartAsync();
        await AssignAsync(host, RootUser(), Alice, TenantAdmin);

        var escalation = await host.SendAsync(User(Alice), HttpMethod.Post, ManagementRoutes.Roles, new CreateRoleRequest("Writers", ["billing.invoices.write"]));
        escalation.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await CodeOf(escalation)).ShouldBe("privilege_escalation");

        var typo = await host.SendAsync(User(Alice), HttpMethod.Post, ManagementRoutes.Roles, new CreateRoleRequest("Typos", ["billing.invoice.read"]));
        (await CodeOf(typo)).ShouldBe("unknown_permission");

        var allowed = await host.SendAsync(User(Alice), HttpMethod.Post, ManagementRoutes.Roles, new CreateRoleRequest("Readers", ["billing.invoices.read"]));
        allowed.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Role_changes_wait_for_a_second_approver()
    {
        await using var host = await StartAsync();
        await AssignAsync(host, RootUser(), Alice, TenantAdmin);
        await AssignAsync(host, RootUser(), Bob, TenantAdmin);
        var role = await host.ReadAsync<RoleDto>(await host.SendAsync(User(Alice), HttpMethod.Post, ManagementRoutes.Roles, new CreateRoleRequest("Readers")));

        var queued = await host.SendAsync(User(Alice), HttpMethod.Post, $"{ManagementRoutes.Roles}/{role.Id}/permissions", new RolePermissionRequest("billing.invoices.read"));
        queued.StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var requestId = (await host.ReadAsync<ChangeOutcomeDto>(queued)).RequestId!.Value;
        (await RolePermissionsAsync(host, role.Id)).ShouldBeEmpty();

        var self = await host.SendAsync(User(Alice), HttpMethod.Post, $"{ManagementRoutes.RoleChanges}/{requestId}/approve", new DecideRoleChangeRequest(null));
        (await CodeOf(self)).ShouldBe("self_decision");

        var approved = await host.SendAsync(User(Bob), HttpMethod.Post, $"{ManagementRoutes.RoleChanges}/{requestId}/approve", new DecideRoleChangeRequest("ok"));
        approved.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await host.ReadAsync<RoleChangeRequestDto>(approved)).Status.ShouldBe("Approved");
        (await RolePermissionsAsync(host, role.Id)).ShouldBe(["billing.invoices.read"]);

        var again = await host.SendAsync(User(Bob), HttpMethod.Post, $"{ManagementRoutes.RoleChanges}/{requestId}/reject", new DecideRoleChangeRequest(null));
        (await CodeOf(again)).ShouldBe("already_decided");
    }

    [Fact]
    public async Task Turning_off_approval_is_itself_approval_gated()
    {
        await using var host = await StartAsync();
        await AssignAsync(host, RootUser(), Alice, TenantAdmin);

        var response = await host.SendAsync(User(Alice), HttpMethod.Put, ManagementRoutes.ApprovalSetting, new SetApprovalSettingRequest(Require: false));

        response.StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var setting = await host.ReadAsync<ApprovalSettingDto>(await host.GetAsync(User(Alice), ManagementRoutes.ApprovalSetting));
        setting.Effective.ShouldBeTrue();
    }

    [Fact]
    public async Task Admins_cannot_act_in_another_tenant()
    {
        await using var host = await StartAsync();
        await AssignAsync(host, RootUser(), Alice, TenantAdmin);
        var roleId = await RoleIdAsync(host, TenantAdmin);

        var response = await host.SendAsync(User(Alice), HttpMethod.Post, ManagementRoutes.Assignments, new AssignRoleRequest(Carol, roleId, TenantB));

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await CodeOf(response)).ShouldBe("not_your_tenant");
    }

    [Fact]
    public async Task Break_glass_needs_an_expiry_and_a_second_approver()
    {
        await using var host = await StartAsync();
        await AssignAsync(host, RootUser(), Alice, TenantAdmin);
        var roleId = await RoleIdAsync(host, BreakGlass);

        var unbounded = await host.SendAsync(User(Alice), HttpMethod.Post, ManagementRoutes.Assignments, new AssignRoleRequest(Carol, roleId, TenantA));
        (await CodeOf(unbounded)).ShouldBe("invalid_expiry");

        var tooLong = await host.SendAsync(User(Alice), HttpMethod.Post, ManagementRoutes.Assignments,
            new AssignRoleRequest(Carol, roleId, TenantA, ExpiresAt: host.Time.GetUtcNow().AddDays(2)));
        (await CodeOf(tooLong)).ShouldBe("invalid_expiry");

        var queued = await host.SendAsync(User(Alice), HttpMethod.Post, ManagementRoutes.Assignments,
            new AssignRoleRequest(Carol, roleId, TenantA, ExpiresAt: host.Time.GetUtcNow().AddHours(2)));
        queued.StatusCode.ShouldBe(HttpStatusCode.Accepted);
        (await host.GetAsync(User(Carol), "/invoices")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Nobody_recertifies_their_own_access()
    {
        await using var host = await StartAsync();
        await AssignAsync(host, RootUser(), Alice, TenantAdmin, expiresAt: DateTimeOffset.UtcNow.AddDays(10));
        var assignment = (await host.ReadAsync<List<AssignmentDto>>(await host.GetAsync(User(Alice), ManagementRoutes.Assignments))).Single();

        var response = await host.SendAsync(User(Alice), HttpMethod.Post, $"{ManagementRoutes.Assignments}/{assignment.Id}/recertify",
            new RecertifyRequest(host.Time.GetUtcNow().AddDays(30)));

        (await CodeOf(response)).ShouldBe("self_recertification");
    }

    [Fact]
    public async Task Expired_assignments_stop_counting_and_are_swept()
    {
        await using var host = await StartAsync();
        await AssignAsync(host, RootUser(), Alice, TenantAdmin);
        await AssignAsync(host, RootUser(), Bob, TenantAdmin, expiresAt: host.Time.GetUtcNow().AddHours(1));

        host.Time.Advance(TimeSpan.FromHours(2));
        await using (var scope = host.Services.CreateAsyncScope())
        {
            var sweep = await scope.ServiceProvider.GetRequiredService<ICommandHandler<SweepExpiredAssignmentsCommand, int>>()
                .HandleAsync(new SweepExpiredAssignmentsCommand(), TestContext.Current.CancellationToken);
            sweep.IsSuccess.ShouldBeTrue();
        }

        var remaining = await host.ReadAsync<List<AssignmentDto>>(await host.GetAsync(User(Alice), ManagementRoutes.Assignments));
        remaining.ShouldHaveSingleItem().UserId.ShouldBe(Alice);
    }

    [Fact]
    public async Task Revoking_an_assignment_takes_effect_for_co_hosted_decisions()
    {
        await using var host = await StartAsync();
        await AssignAsync(host, RootUser(), Alice, TenantAdmin);
        (await host.GetAsync(User(Alice), "/invoices")).StatusCode.ShouldBe(HttpStatusCode.OK);
        var assignment = (await host.ReadAsync<List<AssignmentDto>>(await host.GetAsync(RootUser(), ManagementRoutes.Assignments))).Single();

        (await host.SendAsync(RootUser(), HttpMethod.Delete, $"{ManagementRoutes.Assignments}/{assignment.Id}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        (await host.GetAsync(User(Alice), "/invoices")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Policies_and_scopes_are_for_platform_administrators()
    {
        await using var host = await StartAsync();
        await AssignAsync(host, RootUser(), Alice, TenantAdmin);
        var policy = new UpsertPolicyRequest("No weekend invoices", null, "billing.invoices.write", null, Domain.Policies.PolicyEffect.Deny, """{"attr":"day","op":"eq","value":"sat"}""");

        (await CodeOf(await host.SendAsync(User(Alice), HttpMethod.Post, ManagementRoutes.Policies, policy))).ShouldBe("missing_permission");
        (await CodeOf(await host.SendAsync(User(Alice), HttpMethod.Post, ManagementRoutes.Scopes, new UpsertScopeRequest("team", "Team", null, "tenant")))).ShouldBe("missing_permission");

        (await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.Scopes, new UpsertScopeRequest("team", "Team", null, "tenant"))).StatusCode.ShouldBe(HttpStatusCode.OK);
        var cycle = await host.SendAsync(RootUser(), HttpMethod.Put, $"{ManagementRoutes.Scopes}/tenant", new UpsertScopeRequest("tenant", "Tenant", null, "team"));
        cycle.IsSuccessStatusCode.ShouldBeFalse();
    }

    [Fact]
    public async Task The_read_api_serves_services_granted_the_read_permission()
    {
        await using var host = await StartAsync();

        var service = await host.GetAsync(Service("svc-billing", "authorization.decisions.read"), AuthorizationRoutes.Scopes);
        service.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await host.ReadAsync<List<ScopeDto>>(service)).Count.ShouldBe(4);

        (await host.GetAsync(Service("svc-billing"), AuthorizationRoutes.RolePermissions)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await host.GetAsync(User(Alice), AuthorizationRoutes.UserAssignmentsOf(Alice, TenantA))).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Services_register_permissions_in_their_own_domain_only()
    {
        await using var host = await StartAsync();
        var billing = Service("svc-billing", "authorization.permissions.register");

        var registered = await host.SendAsync(billing, HttpMethod.Post, AuthorizationRoutes.RegisterPermissions,
            new RegisterPermissionsRequest("svc-billing", [new("billing.reports.read", "Read reports", "billing")]));
        registered.StatusCode.ShouldBe(HttpStatusCode.OK);

        var foreign = await host.SendAsync(billing, HttpMethod.Post, AuthorizationRoutes.RegisterPermissions,
            new RegisterPermissionsRequest("svc-billing", [new("crm.contacts.read", "Read contacts", "crm")]));
        (await CodeOf(foreign)).ShouldBe("registration_domain");

        var unpermitted = await host.SendAsync(Service("svc-billing"), HttpMethod.Post, AuthorizationRoutes.RegisterPermissions,
            new RegisterPermissionsRequest("svc-billing", [new("billing.reports.read", "Read reports", "billing")]));
        (await CodeOf(unpermitted)).ShouldBe("missing_permission");

        var catalog = await host.ReadAsync<List<CatalogEntryDto>>(await host.GetAsync(RootUser(), ManagementRoutes.Catalog));
        catalog.ShouldContain(entry => entry.Code == "billing.reports.read" && entry.Source == "svc-billing");
        catalog.ShouldContain(entry => entry.Code == "authorization.roles.write");
    }

    [Fact]
    public async Task A_platform_administrators_pat_is_held_to_its_ceiling_in_management()
    {
        // AUTHZ-1 (docs/security-review.md): a Root member's PAT, limited to reading invoices, must not administer access.
        await using var host = await StartAsync();
        var pat = Principal(("sub", Root.ToString()), ("tid", TenantA.ToString()), ("lvl", "Root"), ("step_up", "mfa"),
            ("cred", "pat"), ("pat_perm", "billing.invoices.read"));
        var roleId = await RoleIdAsync(host, TenantAdmin);

        var response = await host.SendAsync(pat, HttpMethod.Post, ManagementRoutes.Assignments, new AssignRoleRequest(Alice, roleId, TenantA));

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    private static async Task AssignAsync(ManagementHost host, System.Security.Claims.ClaimsPrincipal caller, Guid userId, string roleName, DateTimeOffset? expiresAt = null)
    {
        var roleId = await RoleIdAsync(host, roleName);
        var response = await host.SendAsync(caller, HttpMethod.Post, ManagementRoutes.Assignments, new AssignRoleRequest(userId, roleId, TenantA, ExpiresAt: expiresAt));
        response.StatusCode.ShouldBe(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    private static async Task<Guid> RoleIdAsync(ManagementHost host, string name) =>
        (await host.ReadAsync<List<RoleDto>>(await host.GetAsync(RootUser(), ManagementRoutes.Roles))).Single(role => role.Name == name).Id;

    private static async Task<IReadOnlyList<string>> RolePermissionsAsync(ManagementHost host, Guid roleId) =>
        (await host.ReadAsync<List<RoleDto>>(await host.GetAsync(RootUser(), ManagementRoutes.Roles))).Single(role => role.Id == roleId).Permissions;
}

using System.Net;
using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authorization.Contracts;
using Microsoft.Extensions.DependencyInjection;
using static JeffOps.Authorization.Management.Tests.ManagementHost;

namespace JeffOps.Authorization.Management.Tests;

public sealed class GroupAssignmentTests
{
    private static readonly Guid Engineers = Guid.Parse("e0000000-0000-4000-8000-0000000000e1");
    private static readonly Guid Dana = Guid.Parse("da1a0000-0000-4000-8000-000000000004");
    private static readonly Guid Eve = Guid.Parse("e1e00000-0000-4000-8000-000000000005");

    [Fact]
    public async Task Members_of_a_group_hold_its_roles_while_they_are_members()
    {
        await using var host = await StartAsync();
        var readers = await host.ReadAsync<RoleDto>(await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.Roles, new CreateRoleRequest("Readers", ["billing.invoices.read"])));
        await MembersAsync(host, [Dana]);

        var assigned = await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.GroupAssignments, new AssignGroupRoleRequest(Engineers, readers.Id, TenantA));
        assigned.StatusCode.ShouldBe(HttpStatusCode.OK, await assigned.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        (await host.GetAsync(User(Dana), "/invoices")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await host.GetAsync(User(Eve), "/invoices")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        // Membership follows the provisioning events, and cached decisions follow membership.
        await MembersAsync(host, [Eve], added: [Eve], removed: [Dana]);
        (await host.GetAsync(User(Dana), "/invoices")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await host.GetAsync(User(Eve), "/invoices")).StatusCode.ShouldBe(HttpStatusCode.OK);

        await using (var scope = host.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IEventPublisher>().PublishAsync(new GroupDeletedEvent(TenantA, Engineers, [Eve]), TestContext.Current.CancellationToken);
        }

        (await host.GetAsync(User(Eve), "/invoices")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await host.ReadAsync<List<GroupAssignmentDto>>(await host.GetAsync(RootUser(), ManagementRoutes.GroupAssignments))).ShouldBeEmpty();
    }

    [Fact]
    public async Task Break_glass_roles_are_never_granted_to_groups()
    {
        await using var host = await StartAsync();
        var roles = await host.ReadAsync<List<RoleDto>>(await host.GetAsync(RootUser(), ManagementRoutes.Roles));
        var breakGlass = roles.Single(role => role.Name == BreakGlass);

        var response = await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.GroupAssignments,
            new AssignGroupRoleRequest(Engineers, breakGlass.Id, TenantA, ExpiresAt: host.Time.GetUtcNow().AddHours(1)));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task A_member_cannot_give_their_own_group_permissions_they_lack()
    {
        await using var host = await StartAsync();
        var alice = Guid.NewGuid();
        var admin = (await host.ReadAsync<List<RoleDto>>(await host.GetAsync(RootUser(), ManagementRoutes.Roles))).Single(role => role.Name == TenantAdmin);
        (await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.Assignments, new AssignRoleRequest(alice, admin.Id, TenantA))).StatusCode.ShouldBe(HttpStatusCode.OK);
        var writers = await host.ReadAsync<RoleDto>(await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.Roles, new CreateRoleRequest("Writers", ["billing.invoices.write"])));
        await MembersAsync(host, [alice]);

        var response = await host.SendAsync(User(alice), HttpMethod.Post, ManagementRoutes.GroupAssignments, new AssignGroupRoleRequest(Engineers, writers.Id, TenantA));

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await CodeOf(response)).ShouldBe("privilege_escalation");
    }

    [Fact]
    public async Task Revoking_a_groups_privileged_role_needs_its_permissions()
    {
        await using var host = await StartAsync();
        var carol = Guid.NewGuid();
        var assigners = await host.ReadAsync<RoleDto>(await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.Roles,
            new CreateRoleRequest("Assigners", ["authorization.assignments.read", "authorization.assignments.write"])));
        (await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.Assignments, new AssignRoleRequest(carol, assigners.Id, TenantA))).StatusCode.ShouldBe(HttpStatusCode.OK);
        var admin = (await host.ReadAsync<List<RoleDto>>(await host.GetAsync(RootUser(), ManagementRoutes.Roles))).Single(role => role.Name == TenantAdmin);
        var grant = await host.ReadAsync<GroupAssignmentDto>(await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.GroupAssignments, new AssignGroupRoleRequest(Engineers, admin.Id, TenantA)));

        var response = await host.SendAsync(User(carol), HttpMethod.Delete, $"{ManagementRoutes.GroupAssignments}/{grant.Id}");

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await CodeOf(response)).ShouldBe("privilege_escalation");
    }

    [Fact]
    public async Task A_grantor_who_joins_the_group_does_not_get_permissions_they_lack()
    {
        await using var host = await StartAsync();
        var carol = Guid.NewGuid();
        var assigners = await host.ReadAsync<RoleDto>(await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.Roles,
            new CreateRoleRequest("Assigners", ["authorization.assignments.read", "authorization.assignments.write"])));
        (await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.Assignments, new AssignRoleRequest(carol, assigners.Id, TenantA))).StatusCode.ShouldBe(HttpStatusCode.OK);
        var readers = await host.ReadAsync<RoleDto>(await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.Roles, new CreateRoleRequest("Readers", ["billing.invoices.read"])));
        await MembersAsync(host, [Dana]);

        // Granting a group she isn't in is allowed; joining it afterwards would be a grant to herself.
        (await host.SendAsync(User(carol), HttpMethod.Post, ManagementRoutes.GroupAssignments, new AssignGroupRoleRequest(Engineers, readers.Id, TenantA)))
            .StatusCode.ShouldBe(HttpStatusCode.OK);
        (await host.GetAsync(User(Dana), "/invoices")).StatusCode.ShouldBe(HttpStatusCode.OK);

        await MembersAsync(host, [Dana, carol], added: [carol]);

        (await host.GetAsync(User(carol), "/invoices")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await host.ReadAsync<List<GroupAssignmentDto>>(await host.GetAsync(RootUser(), ManagementRoutes.GroupAssignments))).ShouldBeEmpty();
    }

    private static async Task MembersAsync(ManagementHost host, Guid[] members, Guid[]? added = null, Guid[]? removed = null)
    {
        await using var scope = host.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<IEventPublisher>().PublishAsync(
            new GroupMembershipChangedEvent(TenantA, Engineers, "Engineers", members, added ?? members, removed ?? []),
            TestContext.Current.CancellationToken);
    }
}

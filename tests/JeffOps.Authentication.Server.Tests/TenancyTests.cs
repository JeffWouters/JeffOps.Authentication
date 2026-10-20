using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Application.Features.Federation.CompleteExternalSignIn;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.Tenancy.Endpoints;
using JeffOps.Authentication.Tenancy.Infrastructure;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>
/// Tenancy end to end: the platform tenant and its operators, tenants in sessions, tenant administrators, linked Entra
/// directories, invitations, product signup, SCIM provisioning and a tenant's own SSO provider.
/// </summary>
public sealed class TenancyTests : IAsyncDisposable
{
    private static readonly Guid JeffOpsDirectory = Guid.NewGuid();
    private static readonly Guid ContosoDirectory = Guid.NewGuid();
    private static readonly string OperatorObjectId = Guid.NewGuid().ToString();

    private readonly string _database = TestDatabase.SqliteFile("tenancy");
    private readonly FakeTenantProviders _tenantProviders = new();
    private TokenServerHost _host = null!;

    [Fact]
    public async Task The_configured_operator_runs_the_platform_tenant_and_creates_tenants()
    {
        await StartAsync();
        var operatorId = await EntraSignInAsync(JeffOpsDirectory, OperatorObjectId, "jeff@jeffops.test");
        var operatorToken = (await _host.SignInAsync(operatorId)).AccessToken!;

        var platform = (await GetAsync(operatorToken, TenancyEndpointRouteBuilderExtensions.MembershipsRoute)).EnumerateArray().Single();
        platform.GetProperty("role").GetString().ShouldBe("Admin");

        var created = await PostAsync(operatorToken, TenancyEndpointRouteBuilderExtensions.OperatorRoutes, new { name = "  Contoso   Ltd " });
        created.GetProperty("name").GetString().ShouldBe("Contoso Ltd");
        (await GetAsync(operatorToken, TenancyEndpointRouteBuilderExtensions.OperatorRoutes + "?name=conto")).GetArrayLength().ShouldBe(1);

        var someone = await _host.CreateAccountAsync("someone@example.com");
        var stranger = (await _host.SignInAsync(someone.Id)).AccessToken!;
        (await CodeAsync(await _host.SendAsync(HttpMethod.Get, TenancyEndpointRouteBuilderExtensions.OperatorRoutes, stranger))).ShouldBe("not_allowed");
    }

    [Fact]
    public async Task Members_get_their_tenant_in_tokens_and_lose_it_when_removed_or_the_tenant_is_suspended()
    {
        await StartAsync();
        var operatorToken = await OperatorTokenAsync();
        var member = await _host.CreateAccountAsync("lin@contoso.test");
        var tenant = await CreateTenantAsync(operatorToken, "Contoso", firstAdmin: member.Id);

        (await _host.SignInAsync(member.Id)).Claims("tid").ShouldBe([tenant.ToString()]);

        await PatchAsync(operatorToken, $"{TenancyEndpointRouteBuilderExtensions.OperatorRoutes}/{tenant}", new { status = "Suspended" });
        (await _host.SignInAsync(member.Id)).AccessToken.ShouldBeNull("the account's only tenant is suspended: no session at all (tenant_inactive)");

        await PatchAsync(operatorToken, $"{TenancyEndpointRouteBuilderExtensions.OperatorRoutes}/{tenant}", new { status = "Active" });
        var removed = await _host.SendAsync(HttpMethod.Delete, $"{TenancyEndpointRouteBuilderExtensions.OperatorRoutes}/{tenant}/members/{member.Id}", operatorToken);
        removed.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await _host.SignInAsync(member.Id)).Claims("tid").ShouldBeEmpty();
    }

    [Fact]
    public async Task The_only_administrator_of_a_tenant_can_t_delete_their_account_and_a_member_s_membership_goes_with_it()
    {
        await StartAsync();
        var operatorToken = await OperatorTokenAsync();
        var admin = await _host.CreateAccountAsync("admin@contoso.test");
        var tenant = await CreateTenantAsync(operatorToken, "Contoso", firstAdmin: admin.Id);
        var colleague = await _host.CreateAccountAsync("colleague@contoso.test");
        await PostAsync(operatorToken, $"{TenancyEndpointRouteBuilderExtensions.OperatorRoutes}/{tenant}/members", new { accountId = colleague.Id, role = "Member" });

        var adminToken = (await _host.SignInAsync(admin.Id)).AccessToken!;
        (await CodeAsync(await _host.SendAsync(HttpMethod.Delete, "account", adminToken))).ShouldBe("last_tenant_admin");

        var colleagueToken = (await _host.SignInAsync(colleague.Id)).AccessToken!;
        (await _host.SendAsync(HttpMethod.Delete, "account", colleagueToken)).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await GetAsync(adminToken, TenancyEndpointRouteBuilderExtensions.TenantRoutes + "/members")).GetArrayLength().ShouldBe(1);

        // With another administrator, the first can go.
        var successor = await _host.CreateAccountAsync("successor@contoso.test");
        await PostAsync(operatorToken, $"{TenancyEndpointRouteBuilderExtensions.OperatorRoutes}/{tenant}/members", new { accountId = successor.Id, role = "Admin" });
        (await _host.SendAsync(HttpMethod.Delete, "account", adminToken)).StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task Tenant_administrators_manage_members_but_never_leave_a_tenant_without_one()
    {
        await StartAsync();
        var operatorToken = await OperatorTokenAsync();
        var admin = await _host.CreateAccountAsync("admin@contoso.test");
        var tenant = await CreateTenantAsync(operatorToken, "Contoso", firstAdmin: admin.Id);
        var colleague = await _host.CreateAccountAsync("colleague@contoso.test");
        await PostAsync(operatorToken, $"{TenancyEndpointRouteBuilderExtensions.OperatorRoutes}/{tenant}/members", new { accountId = colleague.Id, role = "Member" });

        var adminToken = (await _host.SignInAsync(admin.Id)).AccessToken!;
        var members = await GetAsync(adminToken, TenancyEndpointRouteBuilderExtensions.TenantRoutes + "/members");
        members.GetArrayLength().ShouldBe(2);

        var lastAdmin = await _host.SendAsync(HttpMethod.Put, $"{TenancyEndpointRouteBuilderExtensions.TenantRoutes}/members/{admin.Id}", adminToken, JsonContent.Create(new { role = "Member" }));
        (await CodeAsync(lastAdmin)).ShouldBe("last_admin");

        var colleagueToken = (await _host.SignInAsync(colleague.Id)).AccessToken!;
        (await CodeAsync(await _host.SendAsync(HttpMethod.Get, TenancyEndpointRouteBuilderExtensions.TenantRoutes + "/members", colleagueToken))).ShouldBe("not_allowed");

        var notSteppedUp = (await _host.SignInAsync(admin.Id, multiFactor: false)).AccessToken!;
        var change = await _host.SendAsync(HttpMethod.Put, $"{TenancyEndpointRouteBuilderExtensions.TenantRoutes}/members/{colleague.Id}", notSteppedUp, JsonContent.Create(new { role = "Admin" }));
        (await CodeAsync(change)).ShouldBe("step_up_required");

        (await PutAsync(adminToken, $"{TenancyEndpointRouteBuilderExtensions.TenantRoutes}/members/{colleague.Id}", new { role = "Admin" }))
            .GetProperty("role").GetString().ShouldBe("Admin");
        (await PutAsync(adminToken, $"{TenancyEndpointRouteBuilderExtensions.TenantRoutes}/members/{admin.Id}", new { role = "Member" }))
            .GetProperty("role").GetString().ShouldBe("Member", "another administrator is left");
    }

    [Fact]
    public async Task People_from_a_linked_entra_directory_join_when_they_sign_in_and_only_owners_link_one()
    {
        await StartAsync();
        var operatorToken = await OperatorTokenAsync();
        var admin = await EntraSignInAsync(ContosoDirectory, Guid.NewGuid().ToString(), "admin@contoso.test");
        var tenant = await CreateTenantAsync(operatorToken, "Contoso", firstAdmin: admin);
        var adminToken = (await _host.SignInAsync(admin)).AccessToken!;

        var foreign = await _host.SendAsync(HttpMethod.Post, TenancyEndpointRouteBuilderExtensions.TenantRoutes + "/directories", adminToken,
            JsonContent.Create(new { entraDirectoryId = Guid.NewGuid() }));
        (await CodeAsync(foreign)).ShouldBe("directory_not_yours");

        await PostAsync(adminToken, TenancyEndpointRouteBuilderExtensions.TenantRoutes + "/directories", new { entraDirectoryId = ContosoDirectory });

        var colleague = await EntraSignInAsync(ContosoDirectory, Guid.NewGuid().ToString(), "colleague@contoso.test");
        (await _host.SignInAsync(colleague)).Claims("tid").ShouldBe([tenant.ToString()]);

        var outsider = await EntraSignInAsync(Guid.NewGuid(), Guid.NewGuid().ToString(), "someone@fabrikam.test");
        (await _host.SignInAsync(outsider)).Claims("tid").ShouldBeEmpty();

        var other = await CreateTenantAsync(operatorToken, "Other");
        var taken = await _host.SendAsync(HttpMethod.Post, $"{TenancyEndpointRouteBuilderExtensions.OperatorRoutes}/{other}/directories", operatorToken,
            JsonContent.Create(new { entraDirectoryId = ContosoDirectory }));
        (await CodeAsync(taken)).ShouldBe("directory_taken");
    }

    [Fact]
    public async Task An_invitation_link_admits_whoever_signs_in_with_it_once()
    {
        await StartAsync();
        var operatorToken = await OperatorTokenAsync();
        var admin = await _host.CreateAccountAsync("admin@contoso.test");
        var tenant = await CreateTenantAsync(operatorToken, "Contoso", firstAdmin: admin.Id);
        var adminToken = (await _host.SignInAsync(admin.Id)).AccessToken!;

        var invitation = await PostAsync(adminToken, TenancyEndpointRouteBuilderExtensions.TenantRoutes + "/invitations", new { email = "new@contoso.test", role = "Admin" });
        var link = new Uri(invitation.GetProperty("link").GetString()!);
        link.AbsolutePath.ShouldStartWith("/invitations/");
        var token = Uri.UnescapeDataString(link.AbsolutePath["/invitations/".Length..]);

        var invitee = await _host.CreateAccountAsync("someone.else@gmail.test");
        var inviteeToken = (await _host.SignInAsync(invitee.Id)).AccessToken!;
        var accepted = await PostAsync(inviteeToken, TenancyEndpointRouteBuilderExtensions.AcceptRoute, new { token });
        accepted.GetProperty("tenantName").GetString().ShouldBe("Contoso");
        accepted.GetProperty("role").GetString().ShouldBe("Admin");
        (await _host.SignInAsync(invitee.Id)).Claims("tid").ShouldBe([tenant.ToString()]);

        var again = await _host.SendAsync(HttpMethod.Post, TenancyEndpointRouteBuilderExtensions.AcceptRoute, inviteeToken, JsonContent.Create(new { token }));
        (await CodeAsync(again)).ShouldBe("invitation_invalid");

        var revoked = await PostAsync(adminToken, TenancyEndpointRouteBuilderExtensions.TenantRoutes + "/invitations", new { });
        var revokedToken = Uri.UnescapeDataString(new Uri(revoked.GetProperty("link").GetString()!).AbsolutePath["/invitations/".Length..]);
        var revoke = await _host.SendAsync(HttpMethod.Delete, $"{TenancyEndpointRouteBuilderExtensions.TenantRoutes}/invitations/{revoked.GetProperty("invitation").GetProperty("id").GetString()}", adminToken);
        revoke.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        var late = await _host.SendAsync(HttpMethod.Post, TenancyEndpointRouteBuilderExtensions.AcceptRoute, inviteeToken, JsonContent.Create(new { token = revokedToken }));
        (await CodeAsync(late)).ShouldBe("invitation_invalid");
    }

    [Fact]
    public async Task The_invitation_page_asks_for_a_sign_in_first()
    {
        await StartAsync();
        var page = await _host.Client.GetAsync(new Uri("invitations/some-token", UriKind.Relative), TestContext.Current.CancellationToken);
        page.StatusCode.ShouldBe(HttpStatusCode.Redirect);
    }

    [Fact]
    public async Task A_products_backend_signs_up_a_tenant_for_its_new_customer_with_the_signup_permission()
    {
        await StartAsync(new()
        {
            ["JeffOps:TokenServer:Clients:1:ServicePermissions:2"] = "auth.tenants.create",
        });
        var founder = await EntraSignInAsync(ContosoDirectory, Guid.NewGuid().ToString(), "founder@contoso.test");
        var service = (await _host.ClientCredentialsAsync(scope: "account")).AccessToken!;

        var signedUp = await PostAsync(service, TenancyEndpointRouteBuilderExtensions.SignupRoute, new { name = "Contoso", adminAccountId = founder, entraDirectoryId = ContosoDirectory });
        var tenant = signedUp.GetProperty("tenant").GetProperty("id").GetGuid();
        (await _host.SignInAsync(founder)).Claims("tid").ShouldBe([tenant.ToString()]);

        var twice = await _host.SendAsync(HttpMethod.Post, TenancyEndpointRouteBuilderExtensions.SignupRoute, service,
            JsonContent.Create(new { name = "Contoso again", adminAccountId = founder, entraDirectoryId = ContosoDirectory }));
        (await CodeAsync(twice)).ShouldBe("directory_taken");

        var user = (await _host.SignInAsync(founder)).AccessToken!;
        (await CodeAsync(await _host.SendAsync(HttpMethod.Post, TenancyEndpointRouteBuilderExtensions.SignupRoute, user,
            JsonContent.Create(new { name = "Mine", adminAccountId = founder })))).ShouldBe("not_allowed");
    }

    [Fact]
    public async Task Scim_adds_members_and_removes_only_the_ones_it_added()
    {
        await StartAsync();
        var operatorToken = await OperatorTokenAsync();
        var invited = await _host.CreateAccountAsync("invited@contoso.test");
        var provisioned = await _host.CreateAccountAsync("provisioned@contoso.test");
        var tenant = await CreateTenantAsync(operatorToken, "Contoso", firstAdmin: invited.Id);

        await using (var scope = _host.Services.CreateAsyncScope())
        {
            var scim = scope.ServiceProvider.GetRequiredService<ITenantMembershipProvisioner>();
            await scim.AddMemberAsync(tenant, provisioned.Id, TestContext.Current.CancellationToken);
            await scim.RemoveMemberAsync(tenant, invited.Id, TestContext.Current.CancellationToken);
        }

        (await _host.SignInAsync(provisioned.Id)).Claims("tid").ShouldBe([tenant.ToString()]);
        (await _host.SignInAsync(invited.Id)).Claims("tid").ShouldBe([tenant.ToString()], "SCIM can't remove a membership it didn't create");

        await using (var scope = _host.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<ITenantMembershipProvisioner>().RemoveMemberAsync(tenant, provisioned.Id, TestContext.Current.CancellationToken);
        }

        (await _host.SignInAsync(provisioned.Id)).Claims("tid").ShouldBeEmpty();
    }

    [Fact]
    public async Task Signing_in_through_a_tenants_own_provider_makes_a_member()
    {
        await StartAsync();
        var operatorToken = await OperatorTokenAsync();
        var tenant = await CreateTenantAsync(operatorToken, "Contoso");
        var provider = TenantProviderNames.OidcPrefix + Guid.NewGuid().ToString("N");
        _tenantProviders.Oidc[provider] = tenant;

        var identity = new ExternalIdentity(provider, new ExternalLoginKey("urn:jeffops:tenant-provider:x", Guid.NewGuid().ToString()), "jo@contoso.test", true, "Jo", AuthenticationStrength.Password);
        var account = await CompleteSignInAsync(identity);

        (await _host.SignInAsync(account)).Claims("tid").ShouldBe([tenant.ToString()]);
    }

    public async ValueTask DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.DisposeAsync();
        }

        TestDatabase.DeleteSqlite(_database);
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private async Task StartAsync(Dictionary<string, string?>? extra = null)
    {
        var settings = new Dictionary<string, string?>
        {
            ["JeffOps:TokenServer:Federation:OpenRegistration"] = "true",
            ["JeffOps:Tenancy:Platform:Name"] = "JeffOps",
            ["JeffOps:Tenancy:Platform:EntraDirectoryId"] = JeffOpsDirectory.ToString(),
            ["JeffOps:Tenancy:Platform:Operators:0:Issuer"] = $"https://login.microsoftonline.com/{JeffOpsDirectory}/v2.0",
            ["JeffOps:Tenancy:Platform:Operators:0:Subject"] = OperatorObjectId,
        };
        foreach (var (key, value) in extra ?? [])
        {
            settings[key] = value;
        }

        _host = await TokenServerHost.StartAsync(
            settings,
            configure: builder =>
            {
                builder.Services.AddSingleton(_tenantProviders);
                builder.Services.AddScoped<ITenantProviderDirectory>(provider => provider.GetRequiredService<FakeTenantProviders>());
                new AuthenticationBuilder(builder.Services, builder.Configuration).AddTenancy().UseTestDatabase(_database);
            },
            map: app => app.MapJeffOpsTenancy());
    }

    /// <summary>The configured operator, signed in through Entra from the platform's directory, stepped up.</summary>
    private async Task<string> OperatorTokenAsync()
    {
        var operatorId = await EntraSignInAsync(JeffOpsDirectory, OperatorObjectId, "jeff@jeffops.test");
        return (await _host.SignInAsync(operatorId)).AccessToken!;
    }

    private async Task<Guid> CreateTenantAsync(string operatorToken, string name, Guid? firstAdmin = null) =>
        (await PostAsync(operatorToken, TenancyEndpointRouteBuilderExtensions.OperatorRoutes, new { name, firstAdmin })).GetProperty("id").GetGuid();

    /// <summary>A sign-in through Entra, as the Entra provider reports it: linked on the directory's issuer and the object id.</summary>
    private Task<Guid> EntraSignInAsync(Guid directory, string objectId, string email) =>
        CompleteSignInAsync(new ExternalIdentity("entra", new ExternalLoginKey($"https://login.microsoftonline.com/{directory}/v2.0", objectId), email, false, email, AuthenticationStrength.Password)
        {
            DirectoryId = directory.ToString(),
        });

    private async Task<Guid> CompleteSignInAsync(ExternalIdentity identity)
    {
        await using var scope = _host.Services.CreateAsyncScope();
        var result = await scope.ServiceProvider.GetRequiredService<ICommandHandler<CompleteExternalSignInCommand, ExternalSignInResult>>()
            .HandleAsync(new CompleteExternalSignInCommand(identity), TestContext.Current.CancellationToken);
        result.IsSuccess.ShouldBeTrue(result.IsSuccess ? null : result.Error.Message);
        return result.Value.AccountId;
    }

    private async Task<JsonElement> GetAsync(string token, string path) =>
        await ReadOkAsync(await _host.SendAsync(HttpMethod.Get, path, token));

    private async Task<JsonElement> PostAsync(string token, string path, object body) =>
        await ReadOkAsync(await _host.SendAsync(HttpMethod.Post, path, token, JsonContent.Create(body)));

    private async Task<JsonElement> PutAsync(string token, string path, object body) =>
        await ReadOkAsync(await _host.SendAsync(HttpMethod.Put, path, token, JsonContent.Create(body)));

    private async Task<JsonElement> PatchAsync(string token, string path, object body) =>
        await ReadOkAsync(await _host.SendAsync(HttpMethod.Patch, path, token, JsonContent.Create(body)));

    private static async Task<JsonElement> ReadOkAsync(HttpResponseMessage response)
    {
        response.StatusCode.ShouldBe(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
    }

    private static async Task<string?> CodeAsync(HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        response.IsSuccessStatusCode.ShouldBeFalse(text);
        using var body = JsonDocument.Parse(text);
        return body.RootElement.TryGetProperty("code", out var code) ? code.GetString() : null;
    }

    /// <summary>Tenants' own providers by name, as the Enterprise module would report them.</summary>
    private sealed class FakeTenantProviders : ITenantProviderDirectory
    {
        public Dictionary<string, Guid> Oidc { get; } = new(StringComparer.Ordinal);

        public Task<TenantSamlProvider?> FindSamlAsync(string name, CancellationToken cancellationToken) => Task.FromResult<TenantSamlProvider?>(null);

        public Task<TenantOidcProvider?> FindOidcAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult(Oidc.TryGetValue(name, out var tenant)
                ? new TenantOidcProvider(name, tenant, "Contoso SSO", new Uri("https://idp.contoso.test/"), "client", null, [], [])
                : null);
    }
}

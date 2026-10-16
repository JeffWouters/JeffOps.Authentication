using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Delegation.Endpoints;
using JeffOps.Authentication.Delegation.Infrastructure;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>Derived BFF sessions: impersonation and tenant switch through the browser's own session.</summary>
public sealed partial class BffTests
{
    private static readonly Guid PlatformTenant = Guid.NewGuid();
    private static readonly Guid PartnerOrganization = Guid.NewGuid();
    private static readonly Guid PartnerTenant = Guid.NewGuid();
    private static readonly Guid CustomerOrganization = Guid.NewGuid();
    private static readonly Guid CustomerTenant = Guid.NewGuid();

    [Fact]
    public async Task Support_impersonates_through_the_bff_until_the_user_revokes()
    {
        await using var delegation = new DelegationSetup();
        await using var stack = await StartAsync(delegation: delegation);
        delegation.Seed(stack.TokenServer);
        var (customer, customerToken) = await DirectUserAsync(stack, "customer@example.com", CustomerTenant, CustomerOrganization);
        var support = await SignInAsync(stack, "support@example.com", id => Member(stack, id, PlatformTenant, null, AccessLevel.Root));

        var grantId = (await BrowserPostAsync(stack, "delegation/impersonation", new { targetUserId = customer })).GetProperty("id").GetString()!;
        (await stack.TokenServer.SendAsync(HttpMethod.Post, $"delegation/impersonation/{grantId}/approve", customerToken)).StatusCode.ShouldBe(HttpStatusCode.OK);

        var started = await BrowserPostAsync(stack, $"bff/impersonation/{grantId}/start");
        started.GetProperty("acting").GetString().ShouldBe("impersonation");
        started.GetProperty("user").GetProperty("sub").GetString().ShouldBe(customer.ToString());
        (await WhoAmIAsync(stack)).ShouldBe(customer.ToString());

        // The user pulls the plug; once the 3-minute token is due, the BFF's re-mint is refused and the acting session ends.
        (await stack.TokenServer.SendAsync(HttpMethod.Post, $"delegation/impersonation/{grantId}/revoke", customerToken)).StatusCode.ShouldBe(HttpStatusCode.OK);
        stack.TokenServer.Time.Advance(TimeSpan.FromMinutes(3));

        var ended = await stack.Browser.GetAsync(new Uri("api/whoami", UriKind.Relative), TestContext.Current.CancellationToken);
        ended.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await WhoAmIAsync(stack)).ShouldBe(support.ToString());
        (await stack.Browser.GetFromJsonAsync<JsonElement>(new Uri("bff/acting", UriKind.Relative), TestContext.Current.CancellationToken))
            .GetProperty("acting").ValueKind.ShouldBe(JsonValueKind.Null);
    }

    [Fact]
    public async Task Stopping_an_impersonation_ends_the_grant_at_the_token_server()
    {
        await using var delegation = new DelegationSetup();
        await using var stack = await StartAsync(delegation: delegation);
        delegation.Seed(stack.TokenServer);
        var (customer, customerToken) = await DirectUserAsync(stack, "customer@example.com", CustomerTenant, CustomerOrganization);
        var support = await SignInAsync(stack, "support@example.com", id => Member(stack, id, PlatformTenant, null, AccessLevel.Root));
        var grantId = (await BrowserPostAsync(stack, "delegation/impersonation", new { targetUserId = customer })).GetProperty("id").GetString()!;
        await stack.TokenServer.SendAsync(HttpMethod.Post, $"delegation/impersonation/{grantId}/approve", customerToken);
        await BrowserPostAsync(stack, $"bff/impersonation/{grantId}/start");

        (await BrowserPostAsync(stack, "bff/acting/stop")).GetProperty("acting").ValueKind.ShouldBe(JsonValueKind.Null);

        (await WhoAmIAsync(stack)).ShouldBe(support.ToString());
        var grant = await (await stack.TokenServer.SendAsync(HttpMethod.Get, $"delegation/impersonation/{grantId}", customerToken))
            .Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        grant.GetProperty("status").GetString().ShouldBe("Ended");
    }

    [Fact]
    public async Task A_partner_switches_tenant_through_the_bff_and_back()
    {
        await using var delegation = new DelegationSetup();
        await using var stack = await StartAsync(delegation: delegation);
        delegation.Seed(stack.TokenServer);
        var partner = await SignInAsync(stack, "partner@example.com", id => Member(stack, id, PartnerTenant, PartnerOrganization));

        var refused = await stack.Browser.SendAsync(Csrf(HttpMethod.Post, $"bff/tenants/{PlatformTenant}/switch"), TestContext.Current.CancellationToken);
        refused.StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        var switched = await BrowserPostAsync(stack, $"bff/tenants/{CustomerTenant}/switch");
        switched.GetProperty("acting").GetString().ShouldBe("tenant-switch");
        switched.GetProperty("user").GetProperty("act_tid").GetString().ShouldBe(CustomerTenant.ToString());
        (await WhoAmIAsync(stack)).ShouldBe(partner.ToString());

        var acting = await stack.Browser.GetFromJsonAsync<JsonElement>(new Uri("bff/acting", UriKind.Relative), TestContext.Current.CancellationToken);
        acting.GetProperty("tenantId").GetString().ShouldBe(CustomerTenant.ToString());

        await BrowserPostAsync(stack, "bff/acting/stop");
        (await stack.Browser.GetFromJsonAsync<JsonElement>(new Uri("bff/acting", UriKind.Relative), TestContext.Current.CancellationToken))
            .GetProperty("acting").ValueKind.ShouldBe(JsonValueKind.Null);
    }

    private static void Member(Stack stack, Guid accountId, Guid tenant, Guid? organization, AccessLevel level = AccessLevel.Tenant) =>
        stack.TokenServer.Tenants.Memberships.GetOrAdd(accountId, _ => []).Add(new TenantMembership(tenant, organization, null, level));

    private static async Task<(Guid Id, string AccessToken)> DirectUserAsync(Stack stack, string email, Guid tenant, Guid? organization)
    {
        var account = await stack.TokenServer.CreateAccountAsync(email);
        Member(stack, account.Id, tenant, organization);
        var tokens = await stack.TokenServer.SignInAsync(account.Id);
        return (account.Id, tokens.AccessToken!);
    }

    private static HttpRequestMessage Csrf(HttpMethod method, string path, object? body = null)
    {
        var request = new HttpRequestMessage(method, path) { Content = body is null ? null : JsonContent.Create(body) };
        request.Headers.Add("X-JeffOps-Csrf", "1");
        return request;
    }

    private static async Task<JsonElement> BrowserPostAsync(Stack stack, string path, object? body = null)
    {
        using var request = Csrf(HttpMethod.Post, path, body);
        var response = await stack.Browser.SendAsync(request, TestContext.Current.CancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
    }

    private static async Task<string?> WhoAmIAsync(Stack stack) =>
        (await stack.Browser.GetFromJsonAsync<JsonElement>(new Uri("api/whoami", UriKind.Relative), TestContext.Current.CancellationToken)).GetProperty("user").GetString();

    /// <summary>The token server side of delegation: the module, its test database, and partner relationships.</summary>
    private sealed class DelegationSetup : IAsyncDisposable
    {
        private readonly string _database = TestDatabase.SqliteFile("bff-delegation");

        public FakeDelegationDirectory Directory { get; } = new();

        public void ConfigureTokenServer(WebApplicationBuilder builder)
        {
            builder.Services.AddSingleton(Directory);
            new AuthenticationBuilder(builder.Services, builder.Configuration)
                .AddDelegation()
                .UseDirectory<FakeDelegationDirectory.Scoped>()
                .UseTestDatabase(_database);
            builder.Services.AddAuthorizationBuilder()
                .AddPolicy("auth.impersonation.initiate", policy => policy.RequireAuthenticatedUser())
                .AddPolicy("auth.impersonation.breakglass", policy => policy.RequireClaim("lvl", nameof(AccessLevel.Root)))
                .AddPolicy("auth.tenant-access.approve", policy => policy.RequireAssertion(_ => false));
        }

        public static void MapTokenServer(WebApplication app) => app.MapJeffOpsDelegation();

        public void Seed(TokenServerHost tokenServer)
        {
            tokenServer.Tenants.Tenants[PlatformTenant] = new TenantInfo(PlatformTenant, null, true);
            tokenServer.Tenants.Tenants[PartnerTenant] = new TenantInfo(PartnerTenant, PartnerOrganization, true);
            tokenServer.Tenants.Tenants[CustomerTenant] = new TenantInfo(CustomerTenant, CustomerOrganization, true);
            Directory.Manage(PartnerOrganization, CustomerTenant, "admin");
        }

        public ValueTask DisposeAsync()
        {
            TestDatabase.DeleteSqlite(_database);

            return ValueTask.CompletedTask;
        }
    }
}

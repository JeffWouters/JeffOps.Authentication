using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Client.DependencyInjection;
using JeffOps.Authentication.Testing;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace JeffOps.Entitlements.Tests;

public sealed class EntitlementTests
{
    private static readonly Guid PaidTenant = Guid.NewGuid();
    private static readonly Guid FreeTenant = Guid.NewGuid();

    [Fact]
    public async Task A_tenant_without_the_entitlement_gets_402_with_the_entitlement_name()
    {
        using var issuer = new TestTokenIssuer();
        await using var app = await StartAsync(issuer, services => services.AddJeffOpsEntitlements<PaidTenantsOnly>());

        (await GetAsync(app, issuer.Token(TestPrincipal.User().InTenant(PaidTenant)))).StatusCode.ShouldBe(HttpStatusCode.OK);

        var refused = await GetAsync(app, issuer.Token(TestPrincipal.User().InTenant(FreeTenant)));
        refused.StatusCode.ShouldBe(HttpStatusCode.PaymentRequired);
        var problem = JsonDocument.Parse(await refused.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).RootElement;
        problem.GetProperty("code").GetString().ShouldBe(EntitlementExtensions.EntitlementRequired);
        problem.GetProperty("entitlement").GetString().ShouldBe("reports.export");
    }

    [Fact]
    public async Task By_default_everything_is_allowed_and_authentication_still_runs_first()
    {
        using var issuer = new TestTokenIssuer();
        await using var app = await StartAsync(issuer, services => services.AddJeffOpsEntitlements());

        (await GetAsync(app, issuer.Token(TestPrincipal.User().InTenant(FreeTenant)))).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await GetAsync(app, token: null)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    private sealed class PaidTenantsOnly : IEntitlementChecker
    {
        public ValueTask<bool> HasAsync(string entitlement, AccessContext access, CancellationToken cancellationToken) =>
            ValueTask.FromResult(access.EffectiveTenantId == PaidTenant);
    }

    private static async Task<WebApplication> StartAsync(TestTokenIssuer issuer, Action<IServiceCollection> entitlements)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["JeffOps:Authentication:Authority"] = TestTokenIssuer.Issuer,
            ["JeffOps:Authentication:Audiences:0"] = "api",
        });
        builder.Services.AddJeffOpsAuthenticationClient(builder.Configuration);
        builder.Services.AddJeffOpsTestTokens(issuer);
        entitlements(builder.Services);

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/export", () => "exported").RequireEntitlement("reports.export");
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<HttpResponseMessage> GetAsync(WebApplication app, string? token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/export");
        if (token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return await app.GetTestClient().SendAsync(request, TestContext.Current.CancellationToken);
    }
}

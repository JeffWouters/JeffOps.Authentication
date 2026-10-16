using System.Net;
using System.Net.Http.Headers;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Client.DependencyInjection;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace JeffOps.Authentication.Testing.Tests;

public sealed class TestTokenIssuerTests
{
    [Fact]
    public async Task A_resource_service_trusts_the_test_issuer_and_reads_the_claims_contract()
    {
        using var issuer = new TestTokenIssuer();
        await using var app = await StartAsync(issuer);
        var tenant = Guid.NewGuid();
        var user = Guid.NewGuid();

        var response = await GetAsync(app, issuer.Token(TestPrincipal.User(user).InTenant(tenant).SteppedUp()));

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).ShouldBe($"{user}|{tenant}|Tenant");
    }

    [Fact]
    public async Task Tokens_of_another_issuer_or_audience_are_rejected()
    {
        using var issuer = new TestTokenIssuer();
        using var stranger = new TestTokenIssuer();
        await using var app = await StartAsync(issuer);

        (await GetAsync(app, stranger.Token(TestPrincipal.User()))).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await GetAsync(app, issuer.Token(TestPrincipal.User(), audience: "other"))).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await GetAsync(app, issuer.Token(TestPrincipal.User(), lifetime: TimeSpan.FromMinutes(-10)))).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public void Principals_carry_the_contract_claims()
    {
        var actor = Guid.NewGuid();
        var claims = TestPrincipal.Service("svc-reports", "reports.read").Claims(Abstractions.Claims.ClaimNames.Default);
        claims.ShouldContain(claim => claim.Type == "lvl" && claim.Value == "Service");
        claims.ShouldContain(claim => claim.Type == "perm" && claim.Value == "reports.read");

        var acting = TestPrincipal.User().ActingIn(Guid.NewGuid(), "readonly").ImpersonatedByActor(actor).Claims(Abstractions.Claims.ClaimNames.Default);
        acting.ShouldContain(claim => claim.Type == "dlg_scope" && claim.Value == "readonly");
        acting.ShouldContain(claim => claim.Type == "act_kind");
    }

    private static async Task<WebApplication> StartAsync(TestTokenIssuer issuer)
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

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/me", (ICurrentUser user, IAccessContextAccessor access) =>
            $"{user.UserId}|{access.GetAccessContext().TenantId}|{access.GetAccessContext().Level}");
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<HttpResponseMessage> GetAsync(WebApplication app, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/me");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await app.GetTestClient().SendAsync(request, TestContext.Current.CancellationToken);
    }
}

using System.Net;
using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authorization.AspNetCore.Data;
using JeffOps.Authorization.AspNetCore.Evaluation;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Decisions;
using JeffOps.Authorization.Domain.Policies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authorization.AspNetCore.Tests;

public sealed class AuthorizerTests
{
    [Fact]
    public async Task The_authorizer_applies_resource_type_policies_with_resource_attributes()
    {
        await using var app = await TestApp.StartAsync(builder =>
            builder.MapGet("/invoices/{amount:int}", async (int amount, IAuthorizer authorizer) =>
            {
                var decision = await authorizer.AuthorizeAsync(new AuthorizationRequest("findings.read")
                {
                    ResourceType = "invoice",
                    Resource = AuthorizationAttributes.Resource(new { amount }),
                });
                return decision.Allowed ? Results.Ok(decision.Code) : Results.Json(decision.Code, statusCode: 403);
            }));

        var reader = Guid.NewGuid();
        app.Data.Assign(reader, FakeDataSource.Reader);
        app.Data.Policies.Add(new(Guid.NewGuid(), "large-invoices", null, "findings.read", "invoice",
            PolicyEffect.Deny, """{"gt":["resource.amount",1000]}""", 0, true));

        async Task<HttpStatusCode> Status(int amount)
        {
            using var request = TestApp.As(TestApp.User(reader), HttpMethod.Get, $"/invoices/{amount}");
            return (await app.Client.SendAsync(request, TestContext.Current.CancellationToken)).StatusCode;
        }

        (await Status(10)).ShouldBe(HttpStatusCode.OK);
        (await Status(5000)).ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task HasPermission_answers_for_the_current_caller()
    {
        await using var app = await TestApp.StartAsync(builder =>
            builder.MapGet("/check/{permission}", async (string permission, IAuthorizer authorizer) =>
                await authorizer.HasPermissionAsync(permission) ? "yes" : "no").RequireAuthorization());

        var reader = Guid.NewGuid();
        app.Data.Assign(reader, FakeDataSource.Reader);

        async Task<string> Ask(string permission)
        {
            using var request = TestApp.As(TestApp.User(reader), HttpMethod.Get, $"/check/{permission}");
            var response = await app.Client.SendAsync(request, TestContext.Current.CancellationToken);
            return await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        }

        (await Ask("findings.read")).ShouldBe("yes");
        (await Ask("findings.write")).ShouldBe("no");
    }
}

public sealed class DecisionCacheTests
{
    private static async Task<HttpStatusCode> GetFindingsAsync(TestApp app, Guid user)
    {
        using var request = TestApp.As(TestApp.User(user), HttpMethod.Get, "/findings");
        return (await app.Client.SendAsync(request, TestContext.Current.CancellationToken)).StatusCode;
    }

    [Fact]
    public async Task Assignments_are_read_once_and_then_served_from_cache()
    {
        await using var app = await TestApp.StartAsync();
        var reader = Guid.NewGuid();
        app.Data.Assign(reader, FakeDataSource.Reader);

        await GetFindingsAsync(app, reader);
        await GetFindingsAsync(app, reader);
        await GetFindingsAsync(app, reader);

        app.Data.AssignmentReads.ShouldBe(1);
    }

    [Fact]
    public async Task A_revocation_event_evicts_the_cached_assignments()
    {
        await using var app = await TestApp.StartAsync();
        var reader = Guid.NewGuid();
        app.Data.Assign(reader, FakeDataSource.Reader);
        (await GetFindingsAsync(app, reader)).ShouldBe(HttpStatusCode.OK);

        app.Data.Assignments.Clear();
        (await GetFindingsAsync(app, reader)).ShouldBe(HttpStatusCode.OK, "still cached");

        await using (var scope = app.Services.CreateAsyncScope())
        {
            var handler = scope.ServiceProvider.GetRequiredService<IIntegrationEventHandler<UserRoleRevokedEvent>>();
            await handler.HandleAsync(new UserRoleRevokedEvent(reader, TestApp.TenantId, FakeDataSource.Reader), TestContext.Current.CancellationToken);
        }

        (await GetFindingsAsync(app, reader)).ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_forged_cache_entry_is_rejected_and_the_source_is_reread()
    {
        await using var app = await TestApp.StartAsync();
        var attacker = Guid.NewGuid();
        var sealedCache = app.Services.GetRequiredService<SealedDecisionCache>();
        var hybrid = app.Services.GetRequiredService<HybridCache>();

        // Plant "attacker holds Admin" with a MAC computed under a different key.
        var storageKey = sealedCache.StorageKey($"assignments:{attacker:N}:{TestApp.TenantId:N}");
        var forged = new SealedCacheEntry(
            "0000000000000000",
            $$"""[{"RoleId":"{{FakeDataSource.Admin}}","ScopeKey":"tenant","ScopeInstanceId":null,"ExpiresAt":null}]""",
            "Zm9yZ2Vk",
            DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeMilliseconds());
        await hybrid.SetAsync(storageKey, forged, cancellationToken: TestContext.Current.CancellationToken);

        (await GetFindingsAsync(app, attacker)).ShouldBe(HttpStatusCode.Forbidden);
        app.Data.AssignmentReads.ShouldBe(1, "the forged entry was replaced from the source");
    }

    [Fact]
    public async Task A_genuine_entry_copied_under_another_key_is_rejected()
    {
        await using var app = await TestApp.StartAsync();
        var admin = Guid.NewGuid();
        var attacker = Guid.NewGuid();
        app.Data.Assign(admin, FakeDataSource.Admin);
        var sealedCache = app.Services.GetRequiredService<SealedDecisionCache>();
        var hybrid = app.Services.GetRequiredService<HybridCache>();

        var adminKey = sealedCache.StorageKey($"assignments:{admin:N}:{TestApp.TenantId:N}");
        var genuine = sealedCache.Seal(adminKey, new[] { new UserAssignmentDto(FakeDataSource.Admin, "tenant", null, null) }, TimeSpan.FromMinutes(5));
        await hybrid.SetAsync(
            sealedCache.StorageKey($"assignments:{attacker:N}:{TestApp.TenantId:N}"), genuine,
            cancellationToken: TestContext.Current.CancellationToken);

        (await GetFindingsAsync(app, attacker)).ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Policies_and_role_permissions_are_compiled_from_the_source() =>
        (await AuthorizationDecisionOf(PolicyEffect.Permit)).Code.ShouldBe(AuthorizationCodes.AllowedByPolicy);

    private static async Task<AuthorizationDecision> AuthorizationDecisionOf(PolicyEffect effect)
    {
        var data = new FakeDataSource();
        data.Policies.Add(new(Guid.NewGuid(), "permit-all", null, "findings.read", null, effect, "{}", 0, true));
        AuthorizationDecision? decision = null;

        await using var app = await TestApp.StartAsync(
            builder => builder.MapGet("/decide", async (IAuthorizer authorizer) =>
            {
                decision = await authorizer.AuthorizeAsync(new AuthorizationRequest("findings.read"));
                return "done";
            }).RequireAuthorization(),
            data: data);

        using var request = TestApp.As(TestApp.User(Guid.NewGuid()), HttpMethod.Get, "/decide");
        await app.Client.SendAsync(request, TestContext.Current.CancellationToken);
        return decision.ShouldNotBeNull();
    }
}

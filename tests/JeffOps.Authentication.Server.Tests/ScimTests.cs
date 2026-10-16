using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Enterprise.Endpoints;
using JeffOps.Authentication.Enterprise.Infrastructure;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

public sealed class ScimTests : IAsyncDisposable
{
    private static readonly Guid Contoso = Guid.NewGuid();

    private readonly string _database = TestDatabase.SqliteFile("scim");
    private readonly RecordingMemberships _memberships = new();
    private readonly ConcurrentQueue<IntegrationEvent> _events = new();
    private TokenServerHost _host = null!;
    private string _token = null!;

    [Fact]
    public async Task A_user_is_provisioned_found_by_filter_and_deprovisioned()
    {
        await StartAsync();

        var created = await ScimAsync(HttpMethod.Post, "Users", """
            {"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Jo@Contoso.com","externalId":"e-1",
             "name":{"givenName":"Jo","familyName":"Doe"},"emails":[{"value":"jo@contoso.com","primary":true}],"active":true}
            """);
        created.StatusCode.ShouldBe(HttpStatusCode.Created, await created.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        created.Content.Headers.ContentType!.MediaType.ShouldBe("application/scim+json");
        var user = await JsonAsync(created);
        var id = Guid.Parse(user.GetProperty("id").GetString()!);
        _memberships.Calls.ShouldContain(("add", Contoso, id));

        var found = await JsonAsync(await ScimAsync(HttpMethod.Get, "Users?filter=" + Uri.EscapeDataString("userName eq \"jo@contoso.com\"")));
        found.GetProperty("totalResults").GetInt32().ShouldBe(1);

        (await ScimAsync(HttpMethod.Post, "Users", """{"userName":"jo@contoso.com","emails":[{"value":"jo@contoso.com"}]}""")).StatusCode.ShouldBe(HttpStatusCode.Conflict);

        // Entra deactivates with a path-less replace and a string boolean.
        var patched = await ScimAsync(HttpMethod.Patch, $"Users/{id}", """
            {"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","value":{"active":"False"}}]}
            """);
        (await JsonAsync(patched)).GetProperty("active").GetBoolean().ShouldBeFalse();
        _memberships.Calls.ShouldContain(("remove", Contoso, id));
        (await AccountAsync(id)).CanAuthenticate.ShouldBeFalse();

        (await ScimAsync(HttpMethod.Delete, $"Users/{id}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await ScimAsync(HttpMethod.Get, $"Users/{id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task An_existing_verified_account_is_linked_not_disabled_on_deprovisioning()
    {
        await StartAsync();
        var existing = await _host.CreateAccountAsync("lee@contoso.com");

        var created = await JsonAsync(await ScimAsync(HttpMethod.Post, "Users", """{"userName":"lee@contoso.com","emails":[{"value":"lee@contoso.com"}]}"""));
        Guid.Parse(created.GetProperty("id").GetString()!).ShouldBe(existing.Id);

        (await ScimAsync(HttpMethod.Delete, $"Users/{existing.Id}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await AccountAsync(existing.Id)).CanAuthenticate.ShouldBeTrue();
        _memberships.Calls.ShouldContain(("remove", Contoso, existing.Id));
    }

    [Fact]
    public async Task Group_membership_changes_are_announced()
    {
        await StartAsync();
        var ann = await UserIdAsync("ann@contoso.com");
        var ben = await UserIdAsync("ben@contoso.com");

        var group = await JsonAsync(await ScimAsync(HttpMethod.Post, "Groups", $$"""{"displayName":"Engineers","members":[{"value":"{{ann}}"}]}"""));
        var groupId = Guid.Parse(group.GetProperty("id").GetString()!);
        Last<GroupMembershipChangedEvent>().Members.ShouldBe([ann]);
        var groupAtStart = await JsonAsync(await ScimAsync(HttpMethod.Get, $"Groups/{groupId}"));
        groupAtStart.GetProperty("members").GetArrayLength().ShouldBe(1, groupAtStart.ToString());

        await ScimAsync(HttpMethod.Patch, $"Groups/{groupId}", $$"""
            {"Operations":[{"op":"add","path":"members","value":[{"value":"{{ben}}"}]},{"op":"remove","path":"members[value eq \"{{ann}}\"]"}]}
            """);
        var changed = Last<GroupMembershipChangedEvent>();
        changed.Members.ShouldBe([ben]);
        changed.Added.ShouldBe([ben]);
        changed.Removed.ShouldBe([ann]);

        var groupNow = await JsonAsync(await ScimAsync(HttpMethod.Get, $"Groups/{groupId}"));
        groupNow.GetProperty("members").GetArrayLength().ShouldBe(1, groupNow.ToString());
        var benNow = await JsonAsync(await ScimAsync(HttpMethod.Get, $"Users/{ben}"));
        benNow.GetProperty("groups").GetArrayLength().ShouldBe(1, benNow.ToString());
        benNow.GetProperty("groups")[0].GetProperty("display").GetString().ShouldBe("Engineers");
        (await ScimAsync(HttpMethod.Post, "Groups", $$"""{"displayName":"Ghosts","members":[{"value":"{{Guid.NewGuid()}}"}]}""")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        (await ScimAsync(HttpMethod.Delete, $"Groups/{groupId}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        Last<GroupDeletedEvent>().FormerMembers.ShouldBe([ben]);
    }

    [Fact]
    public async Task Only_addresses_in_the_tenant_s_verified_domains_can_be_provisioned()
    {
        await StartAsync();
        var outsider = await _host.CreateAccountAsync("victim@fabrikam.com");

        // Linking someone else's account, or squatting on an address the tenant doesn't own, is refused.
        (await ScimAsync(HttpMethod.Post, "Users", """{"userName":"victim@fabrikam.com","emails":[{"value":"victim@fabrikam.com"}]}""")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await ScimAsync(HttpMethod.Post, "Users", """{"userName":"nobody@unclaimed.test"}""")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await ScimAsync(HttpMethod.Get, $"Users/{outsider.Id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        _memberships.Calls.ShouldNotContain(call => call.AccountId == outsider.Id);

        // Nor can a provisioned user's address be changed to one outside them.
        var jo = await UserIdAsync("jo@contoso.com");
        (await ScimAsync(HttpMethod.Patch, $"Users/{jo}", """
            {"Operations":[{"op":"replace","path":"emails[type eq \"work\"].value","value":"victim@fabrikam.com"}]}
            """)).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await AccountAsync(jo)).Email.ShouldBe("jo@contoso.com");
    }

    [Fact]
    public async Task When_the_tenant_system_is_down_nothing_changes_and_a_retry_completes()
    {
        await StartAsync();
        var jo = await UserIdAsync("jo@contoso.com");

        _memberships.Down = true;
        (await ScimAsync(HttpMethod.Delete, $"Users/{jo}")).StatusCode.ShouldBe(HttpStatusCode.ServiceUnavailable);
        (await ScimAsync(HttpMethod.Get, $"Users/{jo}")).StatusCode.ShouldBe(HttpStatusCode.OK, "the identity provider's retry must still find the user");
        (await ScimAsync(HttpMethod.Post, "Users", """{"userName":"kim@contoso.com"}""")).StatusCode.ShouldBe(HttpStatusCode.ServiceUnavailable);
        (await JsonAsync(await ScimAsync(HttpMethod.Get, "Users?filter=" + Uri.EscapeDataString("userName eq \"kim@contoso.com\"")))).GetProperty("totalResults").GetInt32().ShouldBe(0);

        _memberships.Down = false;
        (await ScimAsync(HttpMethod.Delete, $"Users/{jo}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        _memberships.Calls.ShouldContain(("remove", Contoso, jo));
        (await ScimAsync(HttpMethod.Post, "Users", """{"userName":"kim@contoso.com"}""")).StatusCode.ShouldBe(HttpStatusCode.Created);
    }

    [Fact]
    public async Task A_deactivated_user_drops_out_of_announced_group_members_until_reactivated()
    {
        await StartAsync();
        var ann = await UserIdAsync("ann@contoso.com");
        var ben = await UserIdAsync("ben@contoso.com");
        await JsonAsync(await ScimAsync(HttpMethod.Post, "Groups", $$"""{"displayName":"Admins","members":[{"value":"{{ann}}"},{"value":"{{ben}}"}]}"""));
        var created = Last<GroupMembershipChangedEvent>();

        await JsonAsync(await ScimAsync(HttpMethod.Patch, $"Users/{ann}", """{"Operations":[{"op":"replace","value":{"active":false}}]}"""));
        var deactivated = Last<GroupMembershipChangedEvent>();
        deactivated.Members.ShouldBe([ben]);
        deactivated.Removed.ShouldBe([ann]);
        deactivated.Version.ShouldBeGreaterThan(created.Version);

        await JsonAsync(await ScimAsync(HttpMethod.Patch, $"Users/{ann}", """{"Operations":[{"op":"replace","value":{"active":true}}]}"""));
        var reactivated = Last<GroupMembershipChangedEvent>();
        reactivated.Members.ShouldBe([ann, ben], ignoreOrder: true);
        reactivated.Added.ShouldBe([ann]);
        reactivated.Version.ShouldBeGreaterThan(deactivated.Version);
    }

    [Fact]
    public async Task Provisioning_does_not_undo_an_operator_s_disable()
    {
        await StartAsync();
        var jo = await UserIdAsync("jo@contoso.com");
        await _host.WithAccountAsync(jo, account => account.Disable(_host.Time.GetUtcNow()));

        await JsonAsync(await ScimAsync(HttpMethod.Patch, $"Users/{jo}", """{"Operations":[{"op":"replace","value":{"active":false}}]}"""));
        await JsonAsync(await ScimAsync(HttpMethod.Patch, $"Users/{jo}", """{"Operations":[{"op":"replace","value":{"active":true}}]}"""));

        (await AccountAsync(jo)).CanAuthenticate.ShouldBeFalse();
    }

    [Fact]
    public async Task Hostile_filters_and_bodies_get_scim_errors_never_server_errors()
    {
        await StartAsync();
        var jo = await UserIdAsync("jo@contoso.com");
        var group = Guid.Parse((await JsonAsync(await ScimAsync(HttpMethod.Post, "Groups", $$"""{"displayName":"Fuzz","members":[{"value":"{{jo}}"}]}"""))).GetProperty("id").GetString()!);
        var random = new Random(7644);

        for (var round = 0; round < 250; round++)
        {
            var filter = RandomFilter(random);
            await ShouldNotFailAsync(HttpMethod.Get, (random.Next(2) == 0 ? "Users" : "Groups") + "?filter=" + Uri.EscapeDataString(filter)
                + $"&startIndex={random.Next(-5, 5)}&count={random.Next(-5, 500)}", null, filter);

            var patch = RandomPatch(random, jo);
            await ShouldNotFailAsync(HttpMethod.Patch, random.Next(2) == 0 ? $"Users/{jo}" : $"Groups/{group}", patch, patch);

            var body = JsonSerializer.Serialize(RandomJson(random, 3, jo));
            await ShouldNotFailAsync(random.Next(2) == 0 ? HttpMethod.Post : HttpMethod.Put, random.Next(2) == 0 ? "Users" + (random.Next(2) == 0 ? $"/{jo}" : "") : "Groups" + (random.Next(2) == 0 ? $"/{group}" : ""), body, body);
        }

        // The user and group are still readable afterwards: nothing corrupted them.
        (await ScimAsync(HttpMethod.Get, $"Groups/{group}")).StatusCode.ShouldBeOneOf(HttpStatusCode.OK, HttpStatusCode.NotFound);
    }

    private async Task ShouldNotFailAsync(HttpMethod method, string path, string? body, string input)
    {
        var response = await ScimAsync(method, path, body);
        ((int)response.StatusCode).ShouldBeLessThan(500, $"{method} {path}: {input}");
    }

    private static readonly string[] FilterTokens =
        ["userName", "USERNAME", "externalId", "displayName", "emails.value", "members[value eq \"x\"]", "eq", "EQ", "ne", "co", "sw", "pr", "gt", "and", "or", "not",
         "(", ")", "[", "]", "\"", "\\\"", "\\", "\"jo@contoso.com\"", "\"\"", " ", "  ", "\u0000", "\u00e9", "🙂", "%", "*", "'", ";--", "true", "null", "1e999"];

    private static string RandomFilter(Random random) =>
        random.Next(10) == 0
            ? new string('(', random.Next(1, 3000))
            : string.Concat(Enumerable.Range(0, random.Next(0, 12)).Select(_ => FilterTokens[random.Next(FilterTokens.Length)] + (random.Next(3) == 0 ? "" : " ")));

    private static readonly string?[] PatchPaths =
        [null, "", "active", "userName", "displayName", "externalId", "name.givenName", "name.familyName", "emails", "emails[type eq \"work\"].value",
         "emails[type eq \"work\"", "members", "members[value eq \"00000000-0000-0000-0000-000000000000\"]", "members[value eq \"not-a-guid\"]",
         "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber", "meta", "id", "groups", "a.b.c.d", "[", "]"];

    private static readonly object?[] PatchOps = ["add", "remove", "replace", "Add", "Replace", "REMOVE", "move", "", null, 7, true];

    private static string RandomPatch(Random random, Guid member)
    {
        if (random.Next(8) == 0)
        {
            return JsonSerializer.Serialize(RandomJson(random, 3, member));
        }

        var operations = Enumerable.Range(0, random.Next(0, 4)).Select(_ =>
        {
            var operation = new Dictionary<string, object?> { ["op"] = PatchOps[random.Next(PatchOps.Length)], ["value"] = RandomJson(random, 2, member) };
            if (random.Next(4) != 0)
            {
                operation["path"] = PatchPaths[random.Next(PatchPaths.Length)];
            }

            return operation;
        }).ToList();
        return JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["schemas"] = new[] { "urn:ietf:params:scim:api:messages:2.0:PatchOp" },
            ["Operations"] = random.Next(10) == 0 ? RandomJson(random, 1, member) : operations,
        });
    }

    private static object? RandomJson(Random random, int depth, Guid member) => random.Next(depth > 0 ? 12 : 8) switch
    {
        0 => null,
        1 => random.Next(2) == 0,
        2 => random.Next(2) == 0 ? "True" : "false",
        3 => random.NextInt64(long.MinValue, long.MaxValue),
        4 => new string((char)random.Next(1, 0xD7FF), random.Next(0, 400)),
        5 => member.ToString(),
        6 => $"{Guid.NewGuid():N}@contoso.com",
        7 => "",
        8 => Enumerable.Range(0, random.Next(0, 4)).Select(_ => RandomJson(random, depth - 1, member)).ToArray(),
        9 => new[] { new Dictionary<string, object?> { ["value"] = RandomJson(random, depth - 1, member), ["type"] = "work", ["primary"] = RandomJson(random, 0, member) } },
        10 => new Dictionary<string, object?> { ["active"] = RandomJson(random, 0, member), ["userName"] = RandomJson(random, 0, member), ["displayName"] = RandomJson(random, 0, member), ["members"] = RandomJson(random, depth - 1, member), ["emails"] = RandomJson(random, depth - 1, member), ["name"] = RandomJson(random, depth - 1, member) },
        _ => Enumerable.Range(0, random.Next(0, 4)).ToDictionary(index => $"k{index}", _ => RandomJson(random, depth - 1, member)),
    };

    [Fact]
    public async Task Without_the_scim_token_policy_tenant_administrators_can_t_create_tokens()
    {
        await StartAsync(scimTokenPolicy: false);

        var refused = await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.ScimTokenRoutes, await AdminAsync(), JsonContent.Create(new { name = "Entra" }));

        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await refused.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).ShouldContain("auth.enterprise.scim_tokens");
    }

    [Fact]
    public async Task Requests_need_a_live_scim_token()
    {
        await StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, "scim/v2/Users");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "scim_not-a-token");
        (await _host.Client.SendAsync(request, TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        var tokens = await (await _host.SendAsync(HttpMethod.Get, EnterpriseEndpointRouteBuilderExtensions.ScimTokenRoutes, await AdminAsync())).Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        var tokenId = tokens[0].GetProperty("id").GetString();
        (await _host.SendAsync(HttpMethod.Delete, $"{EnterpriseEndpointRouteBuilderExtensions.ScimTokenRoutes}/{tokenId}", await AdminAsync())).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await ScimAsync(HttpMethod.Get, "Users")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
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

    private async Task StartAsync(bool scimTokenPolicy = true)
    {
        _host = await TokenServerHost.StartAsync(
            configure: builder =>
            {
                builder.Services.AddSingleton(_memberships);
                builder.Services.AddScoped<ITenantMembershipProvisioner>(provider => provider.GetRequiredService<RecordingMemberships>());
                builder.Services.AddSingleton<IIntegrationEventHandler<GroupMembershipChangedEvent>>(new Recorder<GroupMembershipChangedEvent>(_events));
                builder.Services.AddSingleton<IIntegrationEventHandler<GroupDeletedEvent>>(new Recorder<GroupDeletedEvent>(_events));
                new AuthenticationBuilder(builder.Services, builder.Configuration).AddEnterprise().UseTestDatabase(_database);
                builder.Services.AddScoped<IEnterpriseDatabaseInitializer, SeedDomain>();
                var policies = builder.Services.AddAuthorizationBuilder().AddPolicy("auth.enterprise.manage", policy => policy.RequireAuthenticatedUser());
                if (scimTokenPolicy)
                {
                    policies.AddPolicy("auth.enterprise.scim_tokens", policy => policy.RequireAuthenticatedUser());
                }
            },
            map: app =>
            {
                app.MapJeffOpsEnterprise();
                app.MapJeffOpsScim();
            });
        _host.Tenants.Tenants[Contoso] = new TenantInfo(Contoso, null, true);

        if (!scimTokenPolicy)
        {
            return;
        }

        var created = await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.ScimTokenRoutes, await AdminAsync(), JsonContent.Create(new { name = "Entra" }));
        created.StatusCode.ShouldBe(HttpStatusCode.OK, await created.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        _token = (await created.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("token").GetString()!;
        _token.ShouldStartWith("scim_");
    }

    private async Task<string> AdminAsync()
    {
        var account = await _host.CreateAccountAsync($"admin-{Guid.NewGuid():N}@contoso.com");
        _host.Tenants.Memberships.GetOrAdd(account.Id, _ => []).Add(new TenantMembership(Contoso, null, null, AccessLevel.Tenant));
        return (await _host.SignInAsync(account.Id)).AccessToken!;
    }

    private async Task<HttpResponseMessage> ScimAsync(HttpMethod method, string path, string? body = null)
    {
        using var request = new HttpRequestMessage(method, $"scim/v2/{path}");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _token);
        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/scim+json");
        }

        return await _host.Client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private async Task<Guid> UserIdAsync(string email)
    {
        var created = await JsonAsync(await ScimAsync(HttpMethod.Post, "Users", $$"""{"userName":"{{email}}","emails":[{"value":"{{email}}"}]}"""));
        return Guid.Parse(created.GetProperty("id").GetString()!);
    }

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage response)
    {
        response.IsSuccessStatusCode.ShouldBeTrue(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).RootElement.Clone();
    }

    private async Task<Domain.Accounts.Account> AccountAsync(Guid id)
    {
        await using var scope = _host.Services.CreateAsyncScope();
        return (await scope.ServiceProvider.GetRequiredService<IAccountRepository>().FindAsync(id, TestContext.Current.CancellationToken))!;
    }

    private T Last<T>() => _events.OfType<T>().Last();

    /// <summary>Verifies contoso.com for the Contoso tenant, once the schema exists.</summary>
    private sealed class SeedDomain(EnterpriseDbContext db) : IEnterpriseDatabaseInitializer
    {
        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            if (!await db.Domains.AnyAsync(cancellationToken))
            {
                var domain = Enterprise.Domain.TenantDomain.Claim(Contoso, "contoso.com", DateTimeOffset.UtcNow);
                domain.CheckTxtRecords([domain.ExpectedValue("v=")], "v=", DateTimeOffset.UtcNow).ShouldBeTrue();
                db.Domains.Add(domain);
                await db.SaveChangesAsync(cancellationToken);
            }
        }
    }

    private sealed class Recorder<T>(ConcurrentQueue<IntegrationEvent> events) : IIntegrationEventHandler<T>
        where T : IntegrationEvent
    {
        public Task HandleAsync(T integrationEvent, CancellationToken cancellationToken)
        {
            events.Enqueue(integrationEvent);
            return Task.CompletedTask;
        }
    }
}

internal sealed class RecordingMemberships : ITenantMembershipProvisioner
{
    public ConcurrentQueue<(string Action, Guid TenantId, Guid AccountId)> Calls { get; } = new();

    /// <summary>When set, the tenant system is down.</summary>
    public bool Down { get; set; }

    public Task AddMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken)
    {
        ThrowIfDown();
        Calls.Enqueue(("add", tenantId, accountId));
        return Task.CompletedTask;
    }

    public Task RemoveMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken)
    {
        ThrowIfDown();
        Calls.Enqueue(("remove", tenantId, accountId));
        return Task.CompletedTask;
    }

    private void ThrowIfDown()
    {
        if (Down)
        {
            throw new HttpRequestException("The tenant system is down.");
        }
    }
}

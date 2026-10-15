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
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

public sealed class ScimTests : IAsyncDisposable
{
    private static readonly Guid Contoso = Guid.NewGuid();

    private readonly string _database = Path.Combine(Path.GetTempPath(), $"jeffops-scim-{Guid.NewGuid():N}.db");
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

        SqliteConnection.ClearAllPools();
        try
        {
            File.Delete(_database);
        }
        catch (IOException)
        {
            // Best effort.
        }
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private async Task StartAsync()
    {
        var connectionString = new SqliteConnectionStringBuilder { DataSource = _database, Pooling = false }.ToString();
        _host = await TokenServerHost.StartAsync(
            configure: builder =>
            {
                builder.Services.AddSingleton(_memberships);
                builder.Services.AddScoped<ITenantMembershipProvisioner>(provider => provider.GetRequiredService<RecordingMemberships>());
                builder.Services.AddSingleton<IIntegrationEventHandler<GroupMembershipChangedEvent>>(new Recorder<GroupMembershipChangedEvent>(_events));
                builder.Services.AddSingleton<IIntegrationEventHandler<GroupDeletedEvent>>(new Recorder<GroupDeletedEvent>(_events));
                builder.Services.AddScoped<IEnterpriseDatabaseInitializer, CreateDatabase>();
                new AuthenticationBuilder(builder.Services, builder.Configuration).AddEnterprise().UseDatabase((_, options) => options.UseSqlite(connectionString));
                builder.Services.AddAuthorizationBuilder().AddPolicy("auth.enterprise.manage", policy => policy.RequireAuthenticatedUser());
            },
            map: app =>
            {
                app.MapJeffOpsEnterprise();
                app.MapJeffOpsScim();
            });
        _host.Tenants.Tenants[Contoso] = new TenantInfo(Contoso, null, true);

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

    private sealed class CreateDatabase(EnterpriseDbContext db) : IEnterpriseDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.EnsureCreatedAsync(cancellationToken);
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

    public Task AddMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken)
    {
        Calls.Enqueue(("add", tenantId, accountId));
        return Task.CompletedTask;
    }

    public Task RemoveMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken)
    {
        Calls.Enqueue(("remove", tenantId, accountId));
        return Task.CompletedTask;
    }
}

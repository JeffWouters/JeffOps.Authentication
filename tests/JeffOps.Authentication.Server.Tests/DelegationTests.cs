using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Delegation.Application;
using JeffOps.Authentication.Delegation.Application.Features.Maintenance;
using JeffOps.Authentication.Delegation.Endpoints;
using JeffOps.Authentication.Delegation.Infrastructure;
using JeffOps.Authentication.SharedKernel.Handlers;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

public sealed class DelegationTests : IAsyncLifetime
{
    private const string ImpersonationGrant = "urn:jeffops:grant-type:impersonation";
    private const string TenantSwitchGrant = "urn:jeffops:grant-type:tenant-switch";

    private static readonly Guid PlatformTenant = Guid.NewGuid();
    private static readonly Guid PartnerOrganization = Guid.NewGuid();
    private static readonly Guid PartnerTenant = Guid.NewGuid();
    private static readonly Guid CustomerOrganization = Guid.NewGuid();
    private static readonly Guid CustomerTenant = Guid.NewGuid();
    private static readonly Guid LockboxTenant = Guid.NewGuid();

    private readonly FakeDelegationDirectory _directory = new();
    private readonly Approvers _approvers = new();
    private readonly string _delegationDatabase = Path.Combine(Path.GetTempPath(), $"jeffops-delegation-{Guid.NewGuid():N}.db");
    private TokenServerHost _host = null!;

    public async ValueTask InitializeAsync()
    {
        var connectionString = new SqliteConnectionStringBuilder { DataSource = _delegationDatabase, Pooling = false }.ToString();
        _host = await TokenServerHost.StartAsync(
            new Dictionary<string, string?>
            {
                ["JeffOps:TokenServer:Clients:0:GrantTypes:2"] = ImpersonationGrant,
                ["JeffOps:TokenServer:Clients:0:GrantTypes:3"] = TenantSwitchGrant,
                ["JeffOps:TokenServer:Clients:2:GrantTypes:2"] = TenantSwitchGrant,
            },
            configure: builder =>
            {
                builder.Services.AddSingleton(_directory);
                builder.Services.AddSingleton(_approvers);
                builder.Services.AddScoped<IDelegationDatabaseInitializer, CreateDelegationDatabase>();
                new AuthenticationBuilder(builder.Services, builder.Configuration)
                    .AddDelegation()
                    .UseDirectory<FakeDelegationDirectory.Scoped>()
                    .UseDatabase((_, options) => options.UseSqlite(connectionString));
                builder.Services.AddAuthorizationBuilder()
                    .AddPolicy("auth.impersonation.initiate", policy => policy.RequireAuthenticatedUser())
                    .AddPolicy("auth.impersonation.breakglass", policy => policy.RequireClaim("lvl", nameof(AccessLevel.Root)))
                    .AddPolicy("auth.tenant-access.approve", policy => policy.RequireAssertion(context =>
                        Guid.TryParse(context.User.FindFirst("sub")?.Value, out var user) && _approvers.Contains(user)));
            },
            map: app => app.MapJeffOpsDelegation());

        var tenants = _host.Tenants;
        tenants.Tenants[PlatformTenant] = new TenantInfo(PlatformTenant, null, true);
        tenants.Tenants[PartnerTenant] = new TenantInfo(PartnerTenant, PartnerOrganization, true);
        tenants.Tenants[CustomerTenant] = new TenantInfo(CustomerTenant, CustomerOrganization, true);
        tenants.Tenants[LockboxTenant] = new TenantInfo(LockboxTenant, CustomerOrganization, true);
        _directory.Manage(PartnerOrganization, CustomerTenant, "admin");
        _directory.Manage(PartnerOrganization, LockboxTenant, "readonly", "billing");
        _directory.Lockbox.Add(LockboxTenant);
    }

    public async ValueTask DisposeAsync()
    {
        await _host.DisposeAsync();
        SqliteConnection.ClearAllPools();
        try
        {
            File.Delete(_delegationDatabase);
        }
        catch (IOException)
        {
            // Best effort.
        }
    }

    // ---- Impersonation -------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Support_acts_as_a_user_after_the_user_approves_and_loses_access_when_they_revoke()
    {
        var (support, supportToken) = await UserAsync("support@example.com", PlatformTenant, null, AccessLevel.Root);
        var (customer, customerToken) = await UserAsync("customer@example.com", CustomerTenant, CustomerOrganization);

        var grant = await PostAsync<JsonElement>(supportToken, "delegation/impersonation", new { targetUserId = customer });
        grant.GetProperty("status").GetString().ShouldBe("PendingApproval");
        var grantId = grant.GetProperty("id").GetString()!;

        (await MintImpersonationAsync(grantId, supportToken)).Error.ShouldBe("invalid_grant");

        var pending = await GetAsync<JsonElement>(customerToken, "delegation/impersonation");
        pending.GetProperty("asTarget").GetArrayLength().ShouldBe(1);
        (await _host.SendAsync(HttpMethod.Post, $"delegation/impersonation/{grantId}/approve", supportToken)).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        (await PostAsync<JsonElement>(customerToken, $"delegation/impersonation/{grantId}/approve")).GetProperty("status").GetString().ShouldBe("Approved");

        var minted = await MintImpersonationAsync(grantId, supportToken);
        minted.Status.ShouldBe(HttpStatusCode.OK, minted.Body.ToString());
        minted.RefreshToken.ShouldBeNull();
        minted.Claims("sub").ShouldBe([customer.ToString()]);
        minted.Claims("tid").ShouldBe([CustomerTenant.ToString()]);
        minted.Claims("grant_id").ShouldBe([grantId]);
        minted.Claims("act_kind").ShouldBe(["Platform"]);
        JsonDocument.Parse(minted.Access.GetPayloadValue<JsonElement>("act").GetRawText()).RootElement.GetProperty("sub").GetString().ShouldBe(support.ToString());
        (minted.Access.ValidTo - minted.Access.IssuedAt).ShouldBeLessThanOrEqualTo(TimeSpan.FromMinutes(3));

        (await PostAsync<JsonElement>(customerToken, $"delegation/impersonation/{grantId}/revoke")).GetProperty("status").GetString().ShouldBe("Revoked");
        (await MintImpersonationAsync(grantId, supportToken)).Code.ShouldBe("grant_invalid");
    }

    [Fact]
    public async Task An_impersonation_session_cannot_start_more_delegation_but_can_end_itself()
    {
        var (_, supportToken) = await UserAsync("support@example.com", PlatformTenant, null, AccessLevel.Root);
        var (customer, customerToken) = await UserAsync("customer@example.com", CustomerTenant, CustomerOrganization);
        var (other, _) = await UserAsync("other@example.com", CustomerTenant, CustomerOrganization);
        var grantId = await ApprovedImpersonationAsync(supportToken, customer, customerToken);
        var impersonating = (await MintImpersonationAsync(grantId, supportToken)).AccessToken!;

        var chained = await _host.SendAsync(HttpMethod.Post, "delegation/impersonation", impersonating, JsonContent.Create(new { targetUserId = other }));
        chained.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await CodeAsync(chained)).ShouldBe("home_session_required");

        (await MintImpersonationAsync(grantId, impersonating)).Code.ShouldBe("home_session_required");

        var ended = await _host.SendAsync(HttpMethod.Post, $"delegation/impersonation/{grantId}/end", impersonating);
        ended.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await MintImpersonationAsync(grantId, supportToken)).Error.ShouldBe("invalid_grant");
    }

    [Fact]
    public async Task Only_the_grant_s_actor_can_mint_against_it()
    {
        var (_, supportToken) = await UserAsync("support@example.com", PlatformTenant, null, AccessLevel.Root);
        var (customer, customerToken) = await UserAsync("customer@example.com", CustomerTenant, CustomerOrganization);
        var grantId = await ApprovedImpersonationAsync(supportToken, customer, customerToken);

        (await MintImpersonationAsync(grantId, customerToken)).Code.ShouldBe("grant_invalid");
        (await MintImpersonationAsync(grantId, actorToken: null)).Code.ShouldBe("actor_required");
        (await MintImpersonationAsync(grantId, "not-a-token")).Code.ShouldBe("token_invalid");
    }

    [Fact]
    public async Task Break_glass_is_for_platform_staff_with_a_reason_and_starts_at_once()
    {
        var (_, supportToken) = await UserAsync("support@example.com", PlatformTenant, null, AccessLevel.Root);
        var (customer, customerToken) = await UserAsync("customer@example.com", CustomerTenant, CustomerOrganization);
        var (_, partnerToken) = await UserAsync("partner@example.com", PartnerTenant, PartnerOrganization);

        (await CodeAsync(await _host.SendAsync(HttpMethod.Post, "delegation/impersonation", supportToken, JsonContent.Create(new { targetUserId = customer, breakGlass = true }))))
            .ShouldBe("reason_required");
        (await CodeAsync(await _host.SendAsync(HttpMethod.Post, "delegation/impersonation", partnerToken, JsonContent.Create(new { targetUserId = customer, breakGlass = true, reason = "outage" }))))
            .ShouldBe("break_glass_platform_only");

        var grant = await PostAsync<JsonElement>(supportToken, "delegation/impersonation", new { targetUserId = customer, breakGlass = true, reason = "Incident 42" });
        grant.GetProperty("status").GetString().ShouldBe("Approved");
        (await MintImpersonationAsync(grant.GetProperty("id").GetString()!, supportToken)).Status.ShouldBe(HttpStatusCode.OK);

        var seenByTarget = await GetAsync<JsonElement>(customerToken, "delegation/impersonation");
        seenByTarget.GetProperty("asTarget")[0].GetProperty("breakGlass").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task Partners_impersonate_only_in_tenants_their_organization_manages()
    {
        var (_, partnerToken) = await UserAsync("partner@example.com", PartnerTenant, PartnerOrganization);
        var (customer, customerToken) = await UserAsync("customer@example.com", CustomerTenant, CustomerOrganization);
        var (stranger, _) = await UserAsync("stranger@example.com", PlatformTenant, null);

        var grantId = await ApprovedImpersonationAsync(partnerToken, customer, customerToken);
        var minted = await MintImpersonationAsync(grantId, partnerToken);
        minted.Claims("act_kind").ShouldBe(["Partner"]);

        (await CodeAsync(await _host.SendAsync(HttpMethod.Post, "delegation/impersonation", partnerToken, JsonContent.Create(new { targetUserId = stranger }))))
            .ShouldBe("not_managed");

        _directory.Unmanage(PartnerOrganization, CustomerTenant);
        (await MintImpersonationAsync(grantId, partnerToken)).Code.ShouldBe("grant_invalid");
    }

    [Fact]
    public async Task Requests_need_a_stepped_up_sign_in()
    {
        var (_, supportToken) = await UserAsync("support@example.com", PlatformTenant, null, AccessLevel.Root, multiFactor: false);
        var (customer, _) = await UserAsync("customer@example.com", CustomerTenant, CustomerOrganization);

        var response = await _host.SendAsync(HttpMethod.Post, "delegation/impersonation", supportToken, JsonContent.Create(new { targetUserId = customer }));

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await CodeAsync(response)).ShouldBe("step_up_required");
    }

    [Fact]
    public async Task Unanswered_requests_expire()
    {
        var (_, supportToken) = await UserAsync("support@example.com", PlatformTenant, null, AccessLevel.Root);
        var (customer, customerToken) = await UserAsync("customer@example.com", CustomerTenant, CustomerOrganization);
        var grantId = (await PostAsync<JsonElement>(supportToken, "delegation/impersonation", new { targetUserId = customer })).GetProperty("id").GetString()!;

        _host.Time.Advance(TimeSpan.FromMinutes(6));
        (await CodeAsync(await _host.SendAsync(HttpMethod.Post, $"delegation/impersonation/{grantId}/approve", customerToken))).ShouldBe("not_pending");

        await using var scope = _host.Services.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<ICommandHandler<ExpireGrantsCommand, int>>().HandleAsync(new ExpireGrantsCommand(), TestContext.Current.CancellationToken);
        (await GetAsync<JsonElement>(supportToken, $"delegation/impersonation/{grantId}")).GetProperty("status").GetString().ShouldBe("Expired");
    }

    // ---- Tenant switch and lockbox -------------------------------------------------------------------------------------

    [Fact]
    public async Task A_partner_switches_into_a_managed_tenant_with_the_relationship_s_ceiling()
    {
        var (partner, partnerToken) = await UserAsync("partner@example.com", PartnerTenant, PartnerOrganization);

        var switched = await MintTenantSwitchAsync(CustomerTenant, partnerToken);

        switched.Status.ShouldBe(HttpStatusCode.OK, switched.Body.ToString());
        switched.RefreshToken.ShouldBeNull();
        switched.Claims("sub").ShouldBe([partner.ToString()]);
        switched.Claims("tid").ShouldBe([PartnerTenant.ToString()]);
        switched.Claims("act_tid").ShouldBe([CustomerTenant.ToString()]);
        switched.Claims("lvl").ShouldBe(["Delegated"]);
        switched.Claims("dlg_scope").ShouldBe(["admin"]);

        (await MintTenantSwitchAsync(PlatformTenant, partnerToken)).Code.ShouldBe("grant_invalid");
        (await MintTenantSwitchAsync(CustomerTenant, switched.AccessToken)).Code.ShouldBe("home_session_required");
    }

    [Fact]
    public async Task A_lockbox_tenant_needs_an_approved_access_grant_that_its_administrator_can_revoke()
    {
        var (_, partnerToken) = await UserAsync("partner@example.com", PartnerTenant, PartnerOrganization);
        var (admin, adminToken) = await UserAsync("admin@example.com", LockboxTenant, CustomerOrganization);
        var (_, memberToken) = await UserAsync("member@example.com", LockboxTenant, CustomerOrganization);
        _approvers.Add(admin);

        (await MintTenantSwitchAsync(LockboxTenant, partnerToken)).Code.ShouldBe("grant_invalid");
        (await CodeAsync(await _host.SendAsync(HttpMethod.Post, "delegation/tenant-access", partnerToken, JsonContent.Create(new { tenantId = CustomerTenant }))))
            .ShouldBe("approval_not_required");

        var grant = await PostAsync<JsonElement>(partnerToken, "delegation/tenant-access", new { tenantId = LockboxTenant });
        var grantId = grant.GetProperty("id").GetString()!;
        (await PostAsync<JsonElement>(partnerToken, "delegation/tenant-access", new { tenantId = LockboxTenant })).GetProperty("id").GetString().ShouldBe(grantId);

        (await GetAsync<JsonElement>(adminToken, "delegation/tenant-access")).GetProperty("intoMyTenant").GetArrayLength().ShouldBe(1);
        (await GetAsync<JsonElement>(memberToken, "delegation/tenant-access")).GetProperty("intoMyTenant").GetArrayLength().ShouldBe(0);
        (await CodeAsync(await _host.SendAsync(HttpMethod.Post, $"delegation/tenant-access/{grantId}/approve", memberToken))).ShouldBe("not_allowed");

        (await PostAsync<JsonElement>(adminToken, $"delegation/tenant-access/{grantId}/approve")).GetProperty("status").GetString().ShouldBe("Approved");
        var switched = await MintTenantSwitchAsync(LockboxTenant, partnerToken);
        switched.Status.ShouldBe(HttpStatusCode.OK, switched.Body.ToString());
        switched.Claims("dlg_scope").ShouldBe(["readonly", "billing"], ignoreOrder: true);

        (await PostAsync<JsonElement>(adminToken, $"delegation/tenant-access/{grantId}/revoke")).GetProperty("status").GetString().ShouldBe("Revoked");
        (await MintTenantSwitchAsync(LockboxTenant, partnerToken)).Code.ShouldBe("grant_invalid");
    }

    [Fact]
    public async Task An_actor_token_only_counts_for_its_own_client_and_scopes()
    {
        var (partner, _) = await UserAsync("partner@example.com", PartnerTenant, PartnerOrganization);
        var narrow = (await _host.SignInAsync(partner, scope: "openid api")).AccessToken!;

        // A token that reached another client (an API it was sent to, say) can't be traded in there.
        var elsewhere = await _host.TokenAsync(new()
        {
            ["grant_type"] = TenantSwitchGrant,
            ["target_tenant"] = CustomerTenant.ToString(),
            ["client_id"] = TokenServerHost.GatewayClient,
            ["client_secret"] = TokenServerHost.GatewaySecret,
            ["scope"] = "api",
            ["actor_token"] = narrow,
            ["actor_token_type"] = "urn:ietf:params:oauth:token-type:access_token",
        });
        elsewhere.Status.ShouldNotBe(HttpStatusCode.OK);
        elsewhere.Code.ShouldBe("token_invalid");

        // Nor widened to scopes the actor token doesn't hold.
        var wider = WithActor(new() { ["grant_type"] = TenantSwitchGrant, ["target_tenant"] = CustomerTenant.ToString() }, narrow);
        wider["scope"] = "api email";
        (await _host.TokenAsync(wider)).Code.ShouldBe("token_invalid");

        (await MintTenantSwitchAsync(CustomerTenant, narrow)).Status.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_dpop_bound_actor_token_needs_its_proof()
    {
        var (partner, _) = await UserAsync("partner@example.com", PartnerTenant, PartnerOrganization);
        using var key = new DpopKey();
        var (location, verifier) = await _host.AuthorizeAsync(partner, scope: "openid api");
        var bound = await DpopTokenAsync(new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = TokenServerHost.QueryValue(location, "code")!,
            ["redirect_uri"] = TokenServerHost.BffRedirect,
            ["code_verifier"] = verifier,
            ["client_id"] = TokenServerHost.BffClient,
            ["client_secret"] = TokenServerHost.BffSecret,
        }, key.Proof("POST", "https://localhost/connect/token"));
        var actorToken = bound.AccessToken!;

        var unproven = await MintTenantSwitchAsync(CustomerTenant, actorToken);
        unproven.Code.ShouldBe("invalid_dpop_proof", unproven.Body.ToString());

        using var thief = new DpopKey();
        var form = WithActor(new() { ["grant_type"] = TenantSwitchGrant, ["target_tenant"] = CustomerTenant.ToString() }, actorToken);
        (await DpopTokenAsync(form, thief.Proof("POST", "https://localhost/connect/token"))).Code.ShouldBe("invalid_dpop_proof");

        var switched = await DpopTokenAsync(form, key.Proof("POST", "https://localhost/connect/token"));
        switched.Status.ShouldBe(HttpStatusCode.OK, switched.Body.ToString());
        switched.Body.GetProperty("token_type").GetString().ShouldBe("DPoP");
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private async Task<(Guid Id, string AccessToken)> UserAsync(string email, Guid tenant, Guid? organization, AccessLevel level = AccessLevel.Tenant, bool multiFactor = true)
    {
        var account = await _host.CreateAccountAsync(email);
        _host.Tenants.Memberships.GetOrAdd(account.Id, _ => []).Add(new TenantMembership(tenant, organization, null, level));
        var tokens = await _host.SignInAsync(account.Id, multiFactor);
        return (account.Id, tokens.AccessToken.ShouldNotBeNull(tokens.Body.ToString()));
    }

    private async Task<string> ApprovedImpersonationAsync(string actorToken, Guid target, string targetToken)
    {
        var grantId = (await PostAsync<JsonElement>(actorToken, "delegation/impersonation", new { targetUserId = target })).GetProperty("id").GetString()!;
        await PostAsync<JsonElement>(targetToken, $"delegation/impersonation/{grantId}/approve");
        return grantId;
    }

    private Task<TokenResponse> MintImpersonationAsync(string grantId, string? actorToken) => _host.TokenAsync(WithActor(new()
    {
        ["grant_type"] = ImpersonationGrant,
        ["grant_id"] = grantId,
    }, actorToken));

    private Task<TokenResponse> MintTenantSwitchAsync(Guid tenant, string? actorToken) => _host.TokenAsync(WithActor(new()
    {
        ["grant_type"] = TenantSwitchGrant,
        ["target_tenant"] = tenant.ToString(),
    }, actorToken));

    private static Dictionary<string, string> WithActor(Dictionary<string, string> form, string? actorToken)
    {
        form["client_id"] = TokenServerHost.BffClient;
        form["client_secret"] = TokenServerHost.BffSecret;
        form["scope"] = "api";
        if (actorToken is not null)
        {
            form["actor_token"] = actorToken;
            form["actor_token_type"] = "urn:ietf:params:oauth:token-type:access_token";
        }

        return form;
    }

    private async Task<TokenResponse> DpopTokenAsync(Dictionary<string, string> form, string proof)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "connect/token") { Content = new FormUrlEncodedContent(form) };
        request.Headers.Add("DPoP", proof);
        var response = await _host.Client.SendAsync(request, TestContext.Current.CancellationToken);
        return new TokenResponse(response.StatusCode, await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken));
    }

    private async Task<T> PostAsync<T>(string token, string path, object? body = null)
    {
        var response = await _host.SendAsync(HttpMethod.Post, path, token, body is null ? null : JsonContent.Create(body));
        response.StatusCode.ShouldBe(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return (await response.Content.ReadFromJsonAsync<T>(TestContext.Current.CancellationToken))!;
    }

    private async Task<T> GetAsync<T>(string token, string path)
    {
        var response = await _host.SendAsync(HttpMethod.Get, path, token);
        response.StatusCode.ShouldBe(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return (await response.Content.ReadFromJsonAsync<T>(TestContext.Current.CancellationToken))!;
    }

    private static async Task<string?> CodeAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        return body.TryGetProperty("code", out var code) ? code.GetString() : null;
    }

    private sealed class CreateDelegationDatabase(DelegationDbContext db) : IDelegationDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.EnsureCreatedAsync(cancellationToken);
    }
}

internal sealed class Approvers : ConcurrentDictionary<Guid, bool>
{
    public void Add(Guid user) => this[user] = true;

    public bool Contains(Guid user) => ContainsKey(user);
}

/// <summary>In-memory partner relationships.</summary>
internal sealed class FakeDelegationDirectory
{
    private readonly ConcurrentDictionary<(Guid Organization, Guid Tenant), string[]> _scopes = new();

    public ConcurrentBag<Guid> Lockbox { get; } = [];

    public void Manage(Guid organization, Guid tenant, params string[] scopes) => _scopes[(organization, tenant)] = scopes;

    public void Unmanage(Guid organization, Guid tenant) => _scopes.TryRemove((organization, tenant), out _);

    internal sealed class Scoped(FakeDelegationDirectory directory) : IDelegationDirectory
    {
        public Task<IReadOnlyList<string>> GetDelegationScopesAsync(Guid organizationId, Guid tenantId, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<string>>(directory._scopes.TryGetValue((organizationId, tenantId), out var scopes) ? scopes : []);

        public Task<bool> RequiresAccessApprovalAsync(Guid tenantId, CancellationToken cancellationToken) =>
            Task.FromResult(directory.Lockbox.Contains(tenantId));
    }
}

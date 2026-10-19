using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Application.Features.Federation.CompleteExternalSignIn;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.Enterprise.Application;
using JeffOps.Authentication.Enterprise.Endpoints;
using JeffOps.Authentication.Enterprise.Infrastructure;
using JeffOps.Authentication.LocalAccounts.Endpoints;
using JeffOps.Authentication.LocalAccounts.Infrastructure;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

public sealed class EnterpriseTests : IAsyncDisposable
{
    private const string CorporateProvider = "corp-idp";
    private static readonly Guid Contoso = Guid.NewGuid();
    private static readonly Guid Fabrikam = Guid.NewGuid();

    private readonly string _enterpriseDatabase = TestDatabase.SqliteFile("enterprise");
    private readonly string _localDatabase = TestDatabase.SqliteFile("enterprise-local");
    private readonly FakeDns _dns = new();
    private readonly ConcurrentDictionary<Guid, bool> _administrators = new();
    private TokenServerHost _host = null!;

    [Fact]
    public async Task A_tenant_verifies_a_domain_through_dns_and_holds_it_alone()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        var other = await AdministratorAsync("admin@fabrikam.com", Fabrikam);

        var claimed = await PostAsync(admin, EnterpriseEndpointRouteBuilderExtensions.DomainRoutes, new { domain = "Contoso.COM" });
        claimed.GetProperty("domain").GetString().ShouldBe("contoso.com");
        claimed.GetProperty("recordName").GetString().ShouldBe("_jeffops-challenge.contoso.com");
        var id = claimed.GetProperty("id").GetString();

        var early = await _host.SendAsync(HttpMethod.Post, $"enterprise/domains/{id}/verify", admin);
        (await CodeAsync(early)).ShouldBe("not_verified");

        _dns.Records["_jeffops-challenge.contoso.com"] = ["unrelated", claimed.GetProperty("recordValue").GetString()!];
        (await PostAsync(admin, $"enterprise/domains/{id}/verify")).GetProperty("status").GetString().ShouldBe("Verified");

        var stolen = await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.DomainRoutes, other, JsonContent.Create(new { domain = "contoso.com" }));
        (await CodeAsync(stolen)).ShouldBe("domain_taken");
    }

    [Fact]
    public async Task Only_stepped_up_tenant_administrators_manage_sign_in_settings()
    {
        await StartAsync();
        var (_, member) = await UserAsync("member@contoso.com", Contoso);
        var notSteppedUp = await AdministratorAsync("admin@contoso.com", Contoso, multiFactor: false);

        (await CodeAsync(await _host.SendAsync(HttpMethod.Get, EnterpriseEndpointRouteBuilderExtensions.DomainRoutes, member))).ShouldBe("not_allowed");
        (await _host.SendAsync(HttpMethod.Get, EnterpriseEndpointRouteBuilderExtensions.DomainRoutes, notSteppedUp)).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await CodeAsync(await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.DomainRoutes, notSteppedUp, JsonContent.Create(new { domain = "contoso.com" }))))
            .ShouldBe("step_up_required");
    }

    [Fact]
    public async Task Without_an_operator_policy_nobody_allows_tenant_providers()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);

        var refused = await _host.SendAsync(HttpMethod.Put, $"enterprise/admin/tenants/{Contoso}/custom-providers", admin, JsonContent.Create(new { allowed = true }));

        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await CodeAsync(refused)).ShouldBe("not_allowed");
    }

    [Fact]
    public async Task Sso_policy_needs_a_known_provider_and_a_verified_domain_for_sso_only()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);

        (await CodeAsync(await _host.SendAsync(HttpMethod.Put, "enterprise/sso", admin, JsonContent.Create(new { provider = "nope", ssoOnly = false })))).ShouldBe("unknown_provider");
        (await CodeAsync(await _host.SendAsync(HttpMethod.Put, "enterprise/sso", admin, JsonContent.Create(new { provider = CorporateProvider, ssoOnly = true })))).ShouldBe("no_verified_domain");

        await VerifyDomainAsync(admin, "contoso.com");
        var policy = await PutAsync(admin, "enterprise/sso", new { provider = CorporateProvider, ssoOnly = true });
        policy.GetProperty("ssoOnly").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task Home_realm_discovery_sends_a_verified_domain_to_the_tenant_s_provider()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await PutAsync(admin, "enterprise/sso", new { provider = CorporateProvider, ssoOnly = false });

        var discovered = await _host.Client.GetAsync(new Uri("account/login/discover?email=jo%40Contoso.com&returnUrl=%2Fdone", UriKind.Relative), TestContext.Current.CancellationToken);
        discovered.Headers.Location!.OriginalString.ShouldStartWith($"/signin/{CorporateProvider}?");

        var elsewhere = await _host.Client.GetAsync(new Uri("account/login/discover?email=jo%40example.org&returnUrl=%2Fdone", UriKind.Relative), TestContext.Current.CancellationToken);
        elsewhere.Headers.Location!.OriginalString.ShouldStartWith("/account/login?");
    }

    [Fact]
    public async Task Sso_only_refuses_passwords_and_other_providers_but_admits_the_tenant_s_provider()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await PutAsync(admin, "enterprise/sso", new { provider = CorporateProvider, ssoOnly = true });

        var register = await _host.SendAsync(HttpMethod.Post, "account/local/register", null, JsonContent.Create(new { email = "new@contoso.com", password = "a long enough password" }));
        (await CodeAsync(register)).ShouldBe("sso_required");

        (await ExternalSignInAsync("other-idp", "jo@contoso.com")).Error.Code.ShouldBe("sso_required");

        // Not on the global allow-list, but the tenant's verified domain admits its own provider.
        var admitted = await ExternalSignInAsync(CorporateProvider, "jo@contoso.com");
        admitted.IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public async Task The_first_sso_sign_in_claims_the_account_the_tenant_provisioned()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await PutAsync(admin, "enterprise/sso", new { provider = CorporateProvider, ssoOnly = false });
        var provisioned = await ProvisionAsync("jo@contoso.com", Contoso);

        var first = await ExternalSignInAsync(CorporateProvider, "jo@contoso.com", subject: "jo-at-idp");
        first.IsSuccess.ShouldBeTrue(first.IsFailure ? first.Error.Message : null);
        first.Value.AccountId.ShouldBe(provisioned, "the provisioned account is claimed, not a second one created");
        first.Value.IsNewAccount.ShouldBeFalse();
        (await ExternalSignInAsync(CorporateProvider, "jo@contoso.com", subject: "jo-at-idp")).Value.AccountId.ShouldBe(provisioned);

        // Another identity at the same provider claiming the same address doesn't take the account over.
        (await ExternalSignInAsync(CorporateProvider, "jo@contoso.com", subject: "someone-else")).Value.AccountId.ShouldNotBe(provisioned);
    }

    [Fact]
    public async Task Accounts_the_tenant_didn_t_provision_are_not_claimed_by_email()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await PutAsync(admin, "enterprise/sso", new { provider = CorporateProvider, ssoOnly = false });
        var selfRegistered = await _host.CreateAccountAsync("lee@contoso.com");

        var signedIn = await ExternalSignInAsync(CorporateProvider, "lee@contoso.com");

        signedIn.Value.AccountId.ShouldNotBe(selfRegistered.Id);
    }

    [Fact]
    public async Task An_existing_account_the_tenant_only_linked_is_attached_after_its_owner_confirms()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await PutAsync(admin, "enterprise/sso", new { provider = CorporateProvider, ssoOnly = true });
        var (cfo, _) = await UserAsync("cfo@contoso.com", Fabrikam);
        await ProvisionAsync("cfo@contoso.com", Contoso, existingAccount: cfo);

        await using (var scope = _host.Services.CreateAsyncScope())
        {
            var refused = await ExternalSignInAsync(CorporateProvider, "cfo@contoso.com", subject: "cfo-at-idp", scope);
            refused.Error.Code.ShouldBe("link_required", "the tenant's provider doesn't take over an account it didn't create");
            var pending = scope.ServiceProvider.GetRequiredService<IPendingLinks>().Current.ShouldNotBeNull();
            pending.AccountId.ShouldBe(cfo);

            // The owner confirms by signing in the usual way (not through the tenant's provider); SSO-only doesn't stop that.
            var confirm = scope.ServiceProvider.GetRequiredService<ICommandHandler<Application.Features.Federation.ConfirmPendingLink.ConfirmPendingLinkCommand, bool>>();
            (await confirm.HandleAsync(new(cfo, CorporateProvider), TestContext.Current.CancellationToken)).Value.ShouldBeFalse("signing in through the asking provider proves nothing");
            (await confirm.HandleAsync(new(cfo, null), TestContext.Current.CancellationToken)).Value.ShouldBeTrue();
        }

        (await ExternalSignInAsync(CorporateProvider, "cfo@contoso.com", subject: "cfo-at-idp")).Value.AccountId.ShouldBe(cfo);
    }

    [Fact]
    public async Task A_pending_link_is_only_confirmed_by_its_own_account()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await PutAsync(admin, "enterprise/sso", new { provider = CorporateProvider, ssoOnly = false });
        var (victim, _) = await UserAsync("victim@contoso.com", Fabrikam);
        await ProvisionAsync("victim@contoso.com", Contoso, existingAccount: victim);
        var (someoneElse, _) = await UserAsync("mallory@contoso.com", Contoso);

        await using (var scope = _host.Services.CreateAsyncScope())
        {
            (await ExternalSignInAsync(CorporateProvider, "victim@contoso.com", subject: "mallory-at-idp", scope)).Error.Code.ShouldBe("link_required");
            var confirm = scope.ServiceProvider.GetRequiredService<ICommandHandler<Application.Features.Federation.ConfirmPendingLink.ConfirmPendingLinkCommand, bool>>();
            (await confirm.HandleAsync(new(someoneElse, null), TestContext.Current.CancellationToken)).Value.ShouldBeFalse();
            scope.ServiceProvider.GetRequiredService<IPendingLinks>().Current.ShouldBeNull("another account's sign-in drops it");
        }

        (await ExternalSignInAsync(CorporateProvider, "victim@contoso.com", subject: "mallory-at-idp")).Error.Code.ShouldBe("link_required");
    }

    [Fact]
    public async Task An_account_provisioning_created_is_claimed_only_while_it_has_nothing_else()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await PutAsync(admin, "enterprise/sso", new { provider = CorporateProvider, ssoOnly = false });
        var provisioned = await ProvisionAsync("sam@contoso.com", Contoso);
        _host.Tenants.Memberships.GetOrAdd(provisioned, _ => []).Add(new TenantMembership(Fabrikam, null, null, AccessLevel.Tenant));

        (await ExternalSignInAsync(CorporateProvider, "sam@contoso.com")).Error.Code.ShouldBe("link_required", "a member of another tenant too");
    }

    [Fact]
    public async Task A_verified_domain_whose_dns_proof_disappears_stops_counting_after_the_grace_period()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await PutAsync(admin, "enterprise/sso", new { provider = CorporateProvider, ssoOnly = true });
        _dns.Records.Clear();

        _host.Time.Advance(TimeSpan.FromDays(2));
        (await RecheckAsync()).ShouldBe(0, "within the grace period");
        (await ExternalSignInAsync("other-idp", "jo@contoso.com")).Error.Code.ShouldBe("sso_required");

        _host.Time.Advance(TimeSpan.FromDays(8));
        (await RecheckAsync()).ShouldBe(1);
        (await ExternalSignInAsync("other-idp", "jo@contoso.com")).Error?.Code.ShouldNotBe("sso_required", "the domain no longer belongs to the tenant here");
    }

    [Fact]
    public async Task Only_operators_take_a_verified_domain_away_from_a_tenant()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");

        (await _host.SendAsync(HttpMethod.Post, "enterprise/admin/domains/contoso.com/revoke", admin)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        await using var scope = _host.Services.CreateAsyncScope();
        var revoke = scope.ServiceProvider.GetRequiredService<ICommandHandler<Enterprise.Application.Features.Domains.RevokeDomainCommand>>();
        (await revoke.HandleAsync(new(Guid.NewGuid(), "CONTOSO.com"), TestContext.Current.CancellationToken)).IsSuccess.ShouldBeTrue();
        (await scope.ServiceProvider.GetRequiredService<IHomeRealmDirectory>().FindByDomainAsync("contoso.com", TestContext.Current.CancellationToken)).ShouldBeNull();
    }

    private async Task<int> RecheckAsync()
    {
        await using var scope = _host.Services.CreateAsyncScope();
        return (await scope.ServiceProvider.GetRequiredService<ICommandHandler<Enterprise.Application.Features.Domains.RecheckDomainsCommand, int>>()
            .HandleAsync(new(), TestContext.Current.CancellationToken)).Value;
    }

    public async ValueTask DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.DisposeAsync();
        }

        TestDatabase.DeleteSqlite(_enterpriseDatabase);
        TestDatabase.DeleteSqlite(_localDatabase);
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private async Task StartAsync()
    {
        _host = await TokenServerHost.StartAsync(
            new()
            {
                ["JeffOps:LocalAccounts:Enabled"] = "true",
                ["JeffOps:LocalAccounts:HashIterations"] = "10000",
                ["JeffOps:TokenServer:Federation:OpenRegistration"] = "false",
                ["JeffOps:Enterprise:RecheckDomains"] = "false",
            },
            configure: builder =>
            {
                builder.Services.AddSingleton(_dns);
                builder.Services.AddSingleton<IExternalIdentityMapper>(new NamedProviders(CorporateProvider, "other-idp"));
                var authentication = new AuthenticationBuilder(builder.Services, builder.Configuration);
                authentication.AddEnterprise().UseDnsResolver<FakeDns.Scoped>().UseTestDatabase(_enterpriseDatabase);
                authentication.AddLocalAccounts().UseTestDatabase(_localDatabase);
                builder.Services.AddAuthorizationBuilder().AddPolicy("auth.enterprise.manage", policy => policy.RequireAssertion(context =>
                    Guid.TryParse(context.User.FindFirst("sub")?.Value, out var user) && _administrators.ContainsKey(user)));
            },
            map: app =>
            {
                app.MapJeffOpsEnterprise();
                app.MapJeffOpsLocalAccounts();
            });
        _host.Tenants.Tenants[Contoso] = new TenantInfo(Contoso, null, true);
        _host.Tenants.Tenants[Fabrikam] = new TenantInfo(Fabrikam, null, true);
    }

    private async Task<(Guid Id, string AccessToken)> UserAsync(string email, Guid tenant, bool multiFactor = true)
    {
        var account = await _host.CreateAccountAsync(email);
        _host.Tenants.Memberships.GetOrAdd(account.Id, _ => []).Add(new TenantMembership(tenant, null, null, AccessLevel.Tenant));
        var tokens = await _host.SignInAsync(account.Id, multiFactor);
        return (account.Id, tokens.AccessToken!);
    }

    private async Task<string> AdministratorAsync(string email, Guid tenant, bool multiFactor = true)
    {
        var (id, token) = await UserAsync(email, tenant, multiFactor);
        _administrators[id] = true;
        return token;
    }

    private async Task VerifyDomainAsync(string admin, string domain)
    {
        var claimed = await PostAsync(admin, EnterpriseEndpointRouteBuilderExtensions.DomainRoutes, new { domain });
        _dns.Records[claimed.GetProperty("recordName").GetString()!] = [claimed.GetProperty("recordValue").GetString()!];
        await PostAsync(admin, $"enterprise/domains/{claimed.GetProperty("id").GetString()}/verify");
    }

    private async Task<Result<ExternalSignInResult>> ExternalSignInAsync(string provider, string email, string? subject = null, AsyncServiceScope? inScope = null)
    {
        var identity = new ExternalIdentity(provider, new ExternalLoginKey("https://idp.test/", subject ?? Guid.NewGuid().ToString()), email, true, "Jo", AuthenticationStrength.Password);
        if (inScope is { } given)
        {
            return await given.ServiceProvider.GetRequiredService<ICommandHandler<CompleteExternalSignInCommand, ExternalSignInResult>>()
                .HandleAsync(new CompleteExternalSignInCommand(identity), TestContext.Current.CancellationToken);
        }

        await using var scope = _host.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<ICommandHandler<CompleteExternalSignInCommand, ExternalSignInResult>>()
            .HandleAsync(new CompleteExternalSignInCommand(identity), TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// An account the tenant's SCIM provisioning created, as the SCIM endpoints would record it; or, with
    /// <paramref name="existingAccount"/>, an existing account it only linked.
    /// </summary>
    private async Task<Guid> ProvisionAsync(string email, Guid tenant, Guid? existingAccount = null)
    {
        var accountId = existingAccount ?? (await _host.CreateAccountAsync(email)).Id;
        await using var scope = _host.Services.CreateAsyncScope();
        scope.ServiceProvider.GetRequiredService<IScimUserRepository>().Add(Enterprise.Domain.ScimUser.Provision(tenant, accountId, createdAccount: existingAccount is null, _host.Time.GetUtcNow()));
        await scope.ServiceProvider.GetRequiredService<IEnterpriseUnitOfWork>().SaveChangesAsync(TestContext.Current.CancellationToken);
        return accountId;
    }

    private async Task<JsonElement> PostAsync(string token, string path, object? body = null) =>
        await ReadOkAsync(await _host.SendAsync(HttpMethod.Post, path, token, body is null ? null : JsonContent.Create(body)));

    private async Task<JsonElement> PutAsync(string token, string path, object body) =>
        await ReadOkAsync(await _host.SendAsync(HttpMethod.Put, path, token, JsonContent.Create(body)));

    private static async Task<JsonElement> ReadOkAsync(HttpResponseMessage response)
    {
        response.StatusCode.ShouldBe(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
    }

    private static async Task<string?> CodeAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        return body.TryGetProperty("code", out var code) ? code.GetString() : null;
    }

    /// <summary>Providers known by name only: enough for discovery and policy, no real sign-in.</summary>
    private sealed class NamedProviders(params string[] names) : IExternalIdentityMapper
    {
        public IReadOnlyCollection<ExternalProviderInfo> Providers { get; } = [.. names.Select(name => new ExternalProviderInfo(name, name))];

        public Result<ExternalIdentity> Map(string provider, ClaimsPrincipal providerClaims) => Error.Failure("unsupported", "Not used in tests.");
    }
}

internal sealed class FakeDns
{
    public ConcurrentDictionary<string, string[]> Records { get; } = new(StringComparer.OrdinalIgnoreCase);

    internal sealed class Scoped(FakeDns dns) : IDnsTxtResolver
    {
        public Task<IReadOnlyList<string>> ResolveTxtAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<string>>(dns.Records.TryGetValue(name, out var values) ? values : []);
    }
}

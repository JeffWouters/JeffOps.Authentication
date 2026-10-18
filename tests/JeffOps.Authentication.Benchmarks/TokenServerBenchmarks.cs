using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.Endpoints;
using JeffOps.Authentication.Enterprise.Endpoints;
using JeffOps.Authentication.Enterprise.Infrastructure;
using JeffOps.Authentication.Enterprise.SqlServer;
using JeffOps.Authentication.Infrastructure.DependencyInjection;
using JeffOps.Authentication.Infrastructure.Persistence;
using JeffOps.Authentication.Persistence.SqlServer;
using JeffOps.Authentication.UI;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Benchmarks;

/// <summary>The token server's protocol endpoints, end to end through an in-process server and a real database.</summary>
[MemoryDiagnoser]
public class TokenEndpointBenchmarks
{
    private BenchHost _host = null!;
    private Guid _account;
    private string _accessToken = null!;
    private string _refreshToken = null!;

    [GlobalSetup]
    public async Task SetupAsync()
    {
        _host = await BenchHost.StartAsync();
        _account = await _host.CreateAccountAsync("ada@example.com");
        var tokens = await _host.SignInAsync(_account);
        _accessToken = tokens.GetProperty("access_token").GetString()!;
        _refreshToken = tokens.GetProperty("refresh_token").GetString()!;
    }

    [GlobalCleanup]
    public Task CleanupAsync() => _host.DisposeAsync().AsTask();

    [Benchmark]
    public Task<JsonElement> ClientCredentials() => _host.TokenAsync(new()
    {
        ["grant_type"] = "client_credentials", ["client_id"] = BenchHost.ServiceClient, ["client_secret"] = BenchHost.ServiceSecret, ["scope"] = "api",
    });

    [Benchmark]
    public Task<JsonElement> AuthorizationCodeFlow() => _host.SignInAsync(_account);

    [Benchmark]
    public async Task<JsonElement> Refresh()
    {
        var renewed = await _host.TokenAsync(new()
        {
            ["grant_type"] = "refresh_token", ["refresh_token"] = _refreshToken, ["client_id"] = BenchHost.BffClient, ["client_secret"] = BenchHost.BffSecret,
        });
        _refreshToken = renewed.GetProperty("refresh_token").GetString()!;
        return renewed;
    }

    [Benchmark]
    public Task<HttpResponseMessage> UserInfo() => _host.SendAsync(HttpMethod.Get, "connect/userinfo", _accessToken);

    [Benchmark]
    public Task<HttpResponseMessage> Introspect() => _host.Client.PostAsync(new Uri("connect/introspect", UriKind.Relative), new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["token"] = _accessToken, ["client_id"] = BenchHost.GatewayClient, ["client_secret"] = BenchHost.GatewaySecret,
    }));

    [Benchmark]
    public Task<HttpResponseMessage> Discovery() => _host.Client.GetAsync(new Uri(".well-known/openid-configuration", UriKind.Relative));
}

/// <summary>SCIM reads an identity provider repeats on every provisioning cycle.</summary>
[MemoryDiagnoser]
public class ScimEndpointBenchmarks
{
    private static readonly Guid Contoso = Guid.NewGuid();
    private BenchHost _host = null!;
    private string _scimToken = null!;
    private string _user = null!;
    private string _enterpriseDatabase = null!;

    [GlobalSetup]
    public async Task SetupAsync()
    {
        _enterpriseDatabase = BenchHost.Pooled(TestDatabase.SqliteFile("bench-scim"));
        _host = await BenchHost.StartAsync(builder =>
        {
            builder.Services.AddScoped<ITenantMembershipProvisioner, NoMemberships>();
            var enterprise = new JeffOps.Authentication.Application.DependencyInjection.AuthenticationBuilder(builder.Services, builder.Configuration).AddEnterprise();
            if (TestDatabase.SqlServer)
            {
                enterprise.AddSqlServerPersistence(migrateOnStartup: true);
            }
            else
            {
                builder.Services.AddScoped<IEnterpriseDatabaseInitializer, CreateEnterprise>();
                enterprise.UseDatabase((_, options) => options.UseSqlite(_enterpriseDatabase));
            }

            builder.Services.AddScoped<IEnterpriseDatabaseInitializer, SeedDomain>();
            builder.Services.AddAuthorizationBuilder()
                .AddPolicy("auth.enterprise.manage", policy => policy.RequireAuthenticatedUser())
                .AddPolicy("auth.enterprise.scim_tokens", policy => policy.RequireAuthenticatedUser());
        },
        app =>
        {
            app.MapJeffOpsEnterprise();
            app.MapJeffOpsScim();
        });
        _host.Tenants.Tenants[Contoso] = new TenantInfo(Contoso, null, true);
        var admin = await _host.CreateAccountAsync("admin@contoso.com", withTenant: false);
        _host.Tenants.Memberships.GetOrAdd(admin, _ => []).Add(new TenantMembership(Contoso, null, null, AccessLevel.Tenant));
        var adminToken = (await _host.SignInAsync(admin)).GetProperty("access_token").GetString()!;
        var created = await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.ScimTokenRoutes, adminToken, JsonContent.Create(new { name = "bench" }));
        _scimToken = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("token").GetString()!;

        var users = new List<string>();
        for (var index = 0; index < 50; index++)
        {
            var response = await ScimAsync(HttpMethod.Post, "Users", $$"""{"userName":"user{{index}}@contoso.com","emails":[{"value":"user{{index}}@contoso.com"}]}""");
            users.Add((await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("id").GetString()!);
        }

        for (var index = 0; index < 5; index++)
        {
            var members = string.Join(',', users.Skip(index * 10).Take(10).Select(id => $$"""{"value":"{{id}}"}"""));
            await ScimAsync(HttpMethod.Post, "Groups", $$"""{"displayName":"Group {{index}}","members":[{{members}}]}""");
        }

        _user = users[0];
    }

    [GlobalCleanup]
    public async Task CleanupAsync()
    {
        await _host.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        TestDatabase.DeleteSqlite(_enterpriseDatabase);
    }

    [Benchmark]
    public Task<HttpResponseMessage> ListUsers() => ScimAsync(HttpMethod.Get, "Users?count=50");

    [Benchmark]
    public Task<HttpResponseMessage> GetUser() => ScimAsync(HttpMethod.Get, $"Users/{_user}");

    [Benchmark]
    public Task<HttpResponseMessage> FilterUsers() => ScimAsync(HttpMethod.Get, "Users?filter=" + Uri.EscapeDataString("userName eq \"user7@contoso.com\""));

    private async Task<HttpResponseMessage> ScimAsync(HttpMethod method, string path, string? body = null)
    {
        using var request = new HttpRequestMessage(method, $"scim/v2/{path}");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _scimToken);
        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/scim+json");
        }

        var response = await _host.Client.SendAsync(request);
        return response.IsSuccessStatusCode ? response : throw new InvalidOperationException($"{method} {path}: {(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
    }

    private sealed class NoMemberships : ITenantMembershipProvisioner
    {
        public Task AddMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RemoveMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class CreateEnterprise(EnterpriseDbContext db) : IEnterpriseDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.EnsureCreatedAsync(cancellationToken);
    }

    private sealed class SeedDomain(EnterpriseDbContext db) : IEnterpriseDatabaseInitializer
    {
        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            if (!await db.Domains.AnyAsync(cancellationToken))
            {
                var domain = Enterprise.Domain.TenantDomain.Claim(Contoso, "contoso.com", TimeProvider.System.GetUtcNow());
                domain.CheckTxtRecords([domain.ExpectedValue("v=")], "v=", TimeProvider.System.GetUtcNow());
                db.Domains.Add(domain);
                await db.SaveChangesAsync(cancellationToken);
            }
        }
    }
}

/// <summary>A token server in process, as the integration tests run it (tests/JeffOps.Authentication.Server.Tests/TokenServerHost.cs).</summary>
internal sealed class BenchHost : IAsyncDisposable
{
    public const string BffClient = "bff";
    public const string BffSecret = "bff-secret-that-is-at-least-thirty-two-characters-long";
    public const string BffRedirect = "https://bff.test/callback";
    public const string ServiceClient = "svc-reports";
    public const string ServiceSecret = "svc-reports-secret-at-least-thirty-two-characters";
    public const string GatewayClient = "gateway";
    public const string GatewaySecret = "gateway-secret-that-is-at-least-thirty-two-characters";

    private readonly WebApplication _app;
    private readonly string _connectionString;

    private BenchHost(WebApplication app, string connectionString, BenchTenants tenants)
    {
        _app = app;
        _connectionString = connectionString;
        Tenants = tenants;
        Client = app.GetTestServer().CreateClient();
        Client.BaseAddress = new Uri("https://localhost/");
    }

    public HttpClient Client { get; }

    public BenchTenants Tenants { get; }

    public static async Task<BenchHost> StartAsync(Action<WebApplicationBuilder>? configure = null, Action<WebApplication>? map = null)
    {
        var tenants = new BenchTenants();
        // Pooled, as a host runs it (the tests' files turn pooling off so they can be deleted at once).
        var connectionString = TestDatabase.SqlServer ? await TestDatabase.CreateSqlServerAsync("bench", CancellationToken.None) : Pooled(TestDatabase.SqliteFile("bench"));
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["JeffOps:TokenServer:Issuer"] = "https://localhost/",
            ["JeffOps:TokenServer:ApiScopes:api:0"] = "api",
            ["JeffOps:TokenServer:RefreshTokenReuseLeeway"] = "00:00:00",
            ["JeffOps:TokenServer:Clients:0:ClientId"] = BffClient,
            ["JeffOps:TokenServer:Clients:0:ClientSecret"] = BffSecret,
            ["JeffOps:TokenServer:Clients:0:GrantTypes:0"] = "authorization_code",
            ["JeffOps:TokenServer:Clients:0:GrantTypes:1"] = "refresh_token",
            ["JeffOps:TokenServer:Clients:0:RedirectUris:0"] = BffRedirect,
            ["JeffOps:TokenServer:Clients:0:Scopes:0"] = "openid",
            ["JeffOps:TokenServer:Clients:0:Scopes:1"] = "profile",
            ["JeffOps:TokenServer:Clients:0:Scopes:2"] = "email",
            ["JeffOps:TokenServer:Clients:0:Scopes:3"] = "offline_access",
            ["JeffOps:TokenServer:Clients:0:Scopes:4"] = "api",
            ["JeffOps:TokenServer:Clients:1:ClientId"] = ServiceClient,
            ["JeffOps:TokenServer:Clients:1:ClientSecret"] = ServiceSecret,
            ["JeffOps:TokenServer:Clients:1:GrantTypes:0"] = "client_credentials",
            ["JeffOps:TokenServer:Clients:1:Scopes:0"] = "api",
            ["JeffOps:TokenServer:Clients:2:ClientId"] = GatewayClient,
            ["JeffOps:TokenServer:Clients:2:ClientSecret"] = GatewaySecret,
            ["JeffOps:TokenServer:Clients:2:GrantTypes:0"] = "client_credentials",
            ["JeffOps:TokenServer:Clients:2:Scopes:0"] = "api",
            ["ConnectionStrings:authentication"] = connectionString,
        });
        builder.Services.AddSingleton<ITenantDirectory>(tenants);
        var authentication = builder.Services.AddJeffOpsAuthentication(builder.Configuration);
        if (TestDatabase.SqlServer)
        {
            authentication.AddSqlServerPersistence(migrateOnStartup: true);
        }
        else
        {
            authentication.UseDatabase((_, options) => options.UseSqlite(connectionString));
        }

        builder.Services.AddAuthentication().AddScheme<AuthenticationSchemeOptions, HeaderSignIn>("JeffOps.SignIn", _ => { });
        builder.Services.AddJeffOpsAuthenticationUI();
        configure?.Invoke(builder);

        var app = builder.Build();
        if (!TestDatabase.SqlServer)
        {
            using var scope = app.Services.CreateScope();
            var database = scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>().Database;
            await database.EnsureCreatedAsync();
            await database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");
        }

        app.UseAuthentication();
        app.UseAuthorization();
        app.UseAntiforgery();
        app.MapJeffOpsAuthentication();
        app.MapJeffOpsAuthenticationUI();
        map?.Invoke(app);
        await app.StartAsync();
        return new BenchHost(app, connectionString, tenants);
    }

    public async Task<Guid> CreateAccountAsync(string email, bool withTenant = true)
    {
        await using var scope = _app.Services.CreateAsyncScope();
        var account = Account.Register(email, "Ada Lovelace", emailVerified: true, TimeProvider.System.GetUtcNow());
        scope.ServiceProvider.GetRequiredService<IAccountRepository>().Add(account);
        await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(CancellationToken.None);
        if (withTenant)
        {
            Tenants.AddMembership(account.Id);
        }

        return account.Id;
    }

    /// <summary>The authorization code flow with PKCE, as a signed-in user.</summary>
    public async Task<JsonElement> SignInAsync(Guid accountId)
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        using var authorize = new HttpRequestMessage(HttpMethod.Get,
            $"connect/authorize?client_id={BffClient}&response_type=code&redirect_uri={Uri.EscapeDataString(BffRedirect)}" +
            $"&scope={Uri.EscapeDataString("openid profile email offline_access api")}&code_challenge={challenge}&code_challenge_method=S256&state=xyz");
        authorize.Headers.Add(HeaderSignIn.Header, $"{accountId}|pwd,mfa|{TimeProvider.System.GetUtcNow().ToUnixTimeSeconds()}");
        var response = await Client.SendAsync(authorize);
        var code = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(response.Headers.Location!.Query)["code"].ToString();
        return await TokenAsync(new()
        {
            ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = BffRedirect, ["code_verifier"] = verifier,
            ["client_id"] = BffClient, ["client_secret"] = BffSecret,
        });
    }

    public async Task<JsonElement> TokenAsync(Dictionary<string, string> form)
    {
        using var content = new FormUrlEncodedContent(form);
        var response = await Client.PostAsync(new Uri("connect/token", UriKind.Relative), content);
        var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
        return response.IsSuccessStatusCode ? body : throw new InvalidOperationException(body.ToString());
    }

    public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string? accessToken, HttpContent? content = null)
    {
        using var request = new HttpRequestMessage(method, path) { Content = content };
        if (accessToken is not null)
        {
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        }

        return await Client.SendAsync(request);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        await TestDatabase.DeleteAsync(_connectionString);
    }

    internal static string Pooled(string sqlite) => new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(sqlite) { Pooling = true }.ToString();

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

/// <summary>Signs in the account named in a header, as the login UI would.</summary>
internal sealed class HeaderSignIn(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string Header = "X-Test-SignIn";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(Header, out var value))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var parts = value.ToString().Split('|');
        var principal = SignInPrincipal.Create(
            Guid.Parse(parts[0]), new AuthenticationStrength(parts[1].Split(',')),
            DateTimeOffset.FromUnixTimeSeconds(long.Parse(parts[2], System.Globalization.CultureInfo.InvariantCulture)), ClaimNames.Default, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name)));
    }
}

/// <summary>An in-memory tenant directory.</summary>
internal sealed class BenchTenants : ITenantDirectory
{
    public ConcurrentDictionary<Guid, List<TenantMembership>> Memberships { get; } = new();

    public ConcurrentDictionary<Guid, TenantInfo> Tenants { get; } = new();

    public void AddMembership(Guid accountId)
    {
        var tenant = Guid.NewGuid();
        Tenants[tenant] = new TenantInfo(tenant, null, true);
        Memberships.GetOrAdd(accountId, _ => []).Add(new TenantMembership(tenant, null, null, AccessLevel.Tenant));
    }

    public Task<IReadOnlyList<TenantMembership>> GetMembershipsAsync(Guid accountId, CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<TenantMembership>>(Memberships.TryGetValue(accountId, out var list) ? [.. list] : []);

    public Task<TenantInfo?> FindTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        Task.FromResult(Tenants.TryGetValue(tenantId, out var tenant) ? tenant : null);
}

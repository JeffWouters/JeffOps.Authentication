using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.Endpoints;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Infrastructure.DependencyInjection;
using JeffOps.Authentication.Infrastructure.Persistence;
using JeffOps.Authentication.UI;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using JeffOps.Authentication.Persistence.SqlServer;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>
/// The token server as a host would run it: real OpenIddict, SQLite in memory, a header-driven sign-in scheme standing in
/// for the login UI, and an in-memory tenant directory.
/// </summary>
internal sealed class TokenServerHost : IAsyncDisposable
{
    public const string BffClient = "bff";
    public const string BffSecret = "bff-secret-that-is-at-least-thirty-two-characters-long";
    public const string BffRedirect = "https://bff.test/callback";
    public const string ServiceClient = "svc-reports";
    public const string ServiceSecret = "svc-reports-secret-at-least-thirty-two-characters";
    public const string GatewayClient = "gateway";
    public const string GatewaySecret = "gateway-secret-that-is-at-least-thirty-two-characters";
    public const string Operator = "operator";

    private readonly WebApplication _app;
    private readonly string _connectionString;

    private TokenServerHost(WebApplication app, string connectionString, FakeTimeProvider time, FakeTenantDirectory tenants)
    {
        _app = app;
        _connectionString = connectionString;
        Time = time;
        Tenants = tenants;
        Client = app.GetTestClient();
        Client.BaseAddress = new Uri("https://localhost/");
    }

    public HttpClient Client { get; }

    /// <summary>The in-process handler, for wiring other clients (a browser with cookies, another server's back channel).</summary>
    public HttpMessageHandler CreateHandler() => _app.GetTestServer().CreateHandler();

    public FakeTimeProvider Time { get; }

    public FakeTenantDirectory Tenants { get; }

    public IServiceProvider Services => _app.Services;

    public static async Task<TokenServerHost> StartAsync(
        Dictionary<string, string?>? overrides = null,
        string environment = "Testing",
        Action<WebApplicationBuilder>? configure = null,
        bool cookieSignIn = false,
        Action<WebApplication>? map = null)
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var tenants = new FakeTenantDirectory();
        // A database per test (TestDatabase): a SQLite file, or a SQL Server database migrated as in production. Every
        // DbContext opens its own connection. Modules a test adds use the same database ("authentication").
        var connectionString = TestDatabase.SqlServer
            ? await TestDatabase.CreateSqlServerAsync("auth", TestContext.Current.CancellationToken)
            : TestDatabase.SqliteFile("auth");
        try
        {
            return await StartAsync(connectionString, time, tenants, overrides, environment, configure, cookieSignIn, map);
        }
        catch
        {
            // A host that fails to start (a startup validation test, say) leaves no database behind.
            await TestDatabase.DeleteAsync(connectionString);
            throw;
        }
    }

    private static async Task<TokenServerHost> StartAsync(
        string connectionString,
        FakeTimeProvider time,
        FakeTenantDirectory tenants,
        Dictionary<string, string?>? overrides,
        string environment,
        Action<WebApplicationBuilder>? configure,
        bool cookieSignIn,
        Action<WebApplication>? map)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = environment });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(Settings(overrides));
        builder.Configuration["ConnectionStrings:authentication"] = connectionString;

        builder.Services.AddSingleton<TimeProvider>(time);
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
        if (cookieSignIn)
        {
            builder.Services.AddAuthentication().AddCookie("JeffOps.SignIn", options => options.LoginPath = "/account/login");
        }
        else
        {
            builder.Services.AddAuthentication()
                .AddScheme<AuthenticationSchemeOptions, HeaderSignIn>("JeffOps.SignIn", _ => { });
        }

        builder.Services.AddJeffOpsAuthenticationUI();
        configure?.Invoke(builder);
        builder.Services.AddAuthorizationBuilder()
            .AddPolicy("auth.accounts.manage", policy => policy.RequireClaim("role", Operator));

        var app = builder.Build();
        if (!TestDatabase.SqlServer)
        {
            using var scope = app.Services.CreateScope();
            var database = scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>().Database;
            await database.EnsureCreatedAsync(TestContext.Current.CancellationToken);

            // WAL: no journal file created and deleted per transaction (which virus scanners on Windows lock, failing a run
            // with "database is locked"), and readers never block the writer.
            await database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;", TestContext.Current.CancellationToken);
        }

        app.UseAuthentication();
        app.UseAuthorization();
        app.UseAntiforgery();
        app.MapJeffOpsAuthentication();
        app.MapJeffOpsAuthenticationUI();
        map?.Invoke(app);
        await app.StartAsync(TestContext.Current.CancellationToken);

        return new TokenServerHost(app, connectionString, time, tenants);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.DisposeAsync();
        await TestDatabase.DeleteAsync(_connectionString);
    }

    public static Dictionary<string, string?> Settings(Dictionary<string, string?>? overrides = null)
    {
        var settings = new Dictionary<string, string?>
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
            ["JeffOps:TokenServer:Clients:1:ServicePermissions:0"] = "auth.accounts.lookup",
            ["JeffOps:TokenServer:Clients:1:ServicePermissions:1"] = "reports.*",

            ["JeffOps:TokenServer:Clients:2:ClientId"] = GatewayClient,
            ["JeffOps:TokenServer:Clients:2:ClientSecret"] = GatewaySecret,
            ["JeffOps:TokenServer:Clients:2:GrantTypes:0"] = "urn:jeffops:grant-type:pat",
            ["JeffOps:TokenServer:Clients:2:GrantTypes:1"] = "client_credentials",
            ["JeffOps:TokenServer:Clients:2:Scopes:0"] = "api",
        };

        foreach (var (key, value) in overrides ?? [])
        {
            settings[key] = value;
        }

        return settings;
    }

    public async Task<Account> CreateAccountAsync(string email = "ada@example.com")
    {
        await using var scope = Services.CreateAsyncScope();
        var account = Account.Register(email, "Ada Lovelace", emailVerified: true, Time.GetUtcNow());
        scope.ServiceProvider.GetRequiredService<IAccountRepository>().Add(account);
        await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(TestContext.Current.CancellationToken);
        return account;
    }

    public async Task WithAccountAsync(Guid accountId, Action<Account> change)
    {
        await using var scope = Services.CreateAsyncScope();
        var account = await scope.ServiceProvider.GetRequiredService<IAccountRepository>().FindAsync(accountId, TestContext.Current.CancellationToken);
        change(account!);
        await scope.ServiceProvider.GetRequiredService<IUnitOfWork>().SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    /// <summary>Runs the authorization code flow with PKCE as a signed-in user and returns the token response.</summary>
    public async Task<TokenResponse> SignInAsync(Guid accountId, bool multiFactor = true, string scope = "openid profile email offline_access api", string? tenantHint = null)
    {
        var (location, verifier) = await AuthorizeAsync(accountId, multiFactor, scope, tenantHint);
        location.ToString().ShouldStartWith(BffRedirect, customMessage: location.ToString());

        var code = QueryValue(location, "code").ShouldNotBeNull();
        return await TokenAsync(new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = BffRedirect,
            ["code_verifier"] = verifier,
            ["client_id"] = BffClient,
            ["client_secret"] = BffSecret,
        });
    }

    public async Task<(Uri Location, string Verifier)> AuthorizeAsync(Guid? accountId, bool multiFactor = true, string scope = "openid api", string? tenantHint = null, string? extra = null)
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var query = $"connect/authorize?client_id={BffClient}&response_type=code&redirect_uri={Uri.EscapeDataString(BffRedirect)}" +
            $"&scope={Uri.EscapeDataString(scope)}&code_challenge={challenge}&code_challenge_method=S256&state=xyz" +
            (tenantHint is null ? "" : $"&tenant_hint={tenantHint}") + (extra ?? "");

        using var request = new HttpRequestMessage(HttpMethod.Get, query);
        if (accountId is { } id)
        {
            request.Headers.Add(HeaderSignIn.Header, $"{id}|{(multiFactor ? "pwd,mfa" : "pwd")}|{Time.GetUtcNow().ToUnixTimeSeconds()}");
        }

        var response = await Client.SendAsync(request, TestContext.Current.CancellationToken);
        response.StatusCode.ShouldBe(HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return (response.Headers.Location!, verifier);
    }

    public async Task<TokenResponse> TokenAsync(Dictionary<string, string> form)
    {
        using var content = new FormUrlEncodedContent(form);
        var response = await Client.PostAsync(new Uri("connect/token", UriKind.Relative), content, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return new TokenResponse(response.StatusCode, JsonDocument.Parse(body).RootElement.Clone());
    }

    public Task<TokenResponse> ClientCredentialsAsync(string clientId = ServiceClient, string secret = ServiceSecret) =>
        TokenAsync(new() { ["grant_type"] = "client_credentials", ["client_id"] = clientId, ["client_secret"] = secret, ["scope"] = "api" });

    public Task<TokenResponse> RefreshAsync(string refreshToken) =>
        TokenAsync(new() { ["grant_type"] = "refresh_token", ["refresh_token"] = refreshToken, ["client_id"] = BffClient, ["client_secret"] = BffSecret });

    public Task<TokenResponse> ExchangePatAsync(string pat) =>
        TokenAsync(new() { ["grant_type"] = "urn:jeffops:grant-type:pat", ["pat"] = pat, ["client_id"] = GatewayClient, ["client_secret"] = GatewaySecret, ["scope"] = "api" });

    public async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string? accessToken, HttpContent? content = null)
    {
        using var request = new HttpRequestMessage(method, path) { Content = content };
        if (accessToken is not null)
        {
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        }

        return await Client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    public static string? QueryValue(Uri uri, string name) =>
        Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query).TryGetValue(name, out var value) ? value.ToString() : null;

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

internal sealed record TokenResponse(HttpStatusCode Status, JsonElement Body)
{
    public string? AccessToken => Body.TryGetProperty("access_token", out var value) ? value.GetString() : null;

    public string? RefreshToken => Body.TryGetProperty("refresh_token", out var value) ? value.GetString() : null;

    public string? IdToken => Body.TryGetProperty("id_token", out var value) ? value.GetString() : null;

    public string? Error => Body.TryGetProperty("error", out var value) ? value.GetString() : null;

    public string? Code => Body.TryGetProperty("code", out var value) ? value.GetString() : null;

    public JsonWebToken Access => new(AccessToken.ShouldNotBeNull(Body.ToString()));

    public IReadOnlyList<string> Claims(string type) => [.. Access.Claims.Where(claim => claim.Type == type).Select(claim => claim.Value)];
}

/// <summary>Stands in for the login UI: "account|methods|authTime" in a header signs the user in.</summary>
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
            Guid.Parse(parts[0]),
            new AuthenticationStrength(parts[1].Split(',')),
            DateTimeOffset.FromUnixTimeSeconds(long.Parse(parts[2], System.Globalization.CultureInfo.InvariantCulture)),
            ClaimNames.Default,
            Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name)));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Redirect("/login?returnUrl=" + Uri.EscapeDataString(properties.RedirectUri ?? "/"));
        return Task.CompletedTask;
    }
}

/// <summary>An in-memory tenant directory; can be made to fail.</summary>
internal sealed class FakeTenantDirectory : ITenantDirectory
{
    public ConcurrentDictionary<Guid, List<TenantMembership>> Memberships { get; } = new();

    public ConcurrentDictionary<Guid, TenantInfo> Tenants { get; } = new();

    public bool Unavailable { get; set; }

    public Guid AddMembership(Guid accountId, AccessLevel level = AccessLevel.Tenant, bool acceptsSessions = true)
    {
        var tenant = Guid.NewGuid();
        Tenants[tenant] = new TenantInfo(tenant, null, acceptsSessions);
        Memberships.GetOrAdd(accountId, _ => []).Add(new TenantMembership(tenant, null, null, level));
        return tenant;
    }

    public Task<IReadOnlyList<TenantMembership>> GetMembershipsAsync(Guid accountId, CancellationToken cancellationToken) =>
        Unavailable
            ? throw new HttpRequestException("directory down")
            : Task.FromResult<IReadOnlyList<TenantMembership>>(Memberships.TryGetValue(accountId, out var list) ? [.. list] : []);

    public Task<TenantInfo?> FindTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        Unavailable
            ? throw new HttpRequestException("directory down")
            : Task.FromResult(Tenants.TryGetValue(tenantId, out var tenant) ? tenant : null);
}

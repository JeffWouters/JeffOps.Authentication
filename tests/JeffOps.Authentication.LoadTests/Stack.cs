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
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Bff;
using JeffOps.Authentication.Bff.Yarp;
using JeffOps.Authentication.Client.DependencyInjection;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.Endpoints;
using JeffOps.Authentication.Enterprise.Endpoints;
using JeffOps.Authentication.Enterprise.Infrastructure;
using JeffOps.Authentication.Enterprise.SqlServer;
using JeffOps.Authentication.Infrastructure.DependencyInjection;
using JeffOps.Authentication.Infrastructure.Persistence;
using JeffOps.Authentication.Persistence.SqlServer;
using JeffOps.Authentication.Tests.Shared;
using JeffOps.Authentication.UI;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.AspNetCore.DependencyInjection;
using JeffOps.Authorization.Domain.Permissions;
using JeffOps.Authorization.Domain.Management;
using JeffOps.Authorization.Endpoints;
using JeffOps.Authorization.Infrastructure.DependencyInjection;
using JeffOps.Authorization.Infrastructure.Persistence;
using JeffOps.Authorization.Persistence.SqlServer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace JeffOps.Authentication.LoadTests;

/// <summary>How the stack is set up for a run.</summary>
internal sealed record StackOptions(bool Logging, TimeSpan DirectoryLatency, TimeSpan DatabaseLatency, bool RecommendedLogLevels = false);

/// <summary>
/// The platform in one process: the token server (with the Enterprise module for SCIM), the management service, a resource
/// API using the Authorization package and token validation, and the BFF proxying to that API. They reach each other by
/// host name through in-process handlers, as the integration tests wire them; each has its own database.
/// </summary>
internal sealed class Stack : IAsyncDisposable
{
    public const string Issuer = "https://localhost/";
    public const string ApiUrl = "https://api.test/api/orders";
    public static readonly Guid Tenant = Guid.Parse("10adbeef-0000-4000-8000-000000000001");

    public const string BffClient = "bff";
    public const string BffSecret = "bff-secret-that-is-at-least-thirty-two-characters-long";
    public const string BffRedirect = "https://bff.test/callback";
    public const string LoadClient = "load-svc";
    public const string LoadSecret = "load-svc-secret-that-is-at-least-thirty-two-chars";
    public const string DpopClient = "dpop-svc";
    public const string DpopSecret = "dpop-svc-secret-that-is-at-least-thirty-two-chars";
    private const string ApiServiceClient = "orders-api";
    private const string ApiServiceSecret = "orders-api-secret-that-is-at-least-thirty-two-chars";
    private const string SpaBffClient = "spa-bff";
    private const string SpaBffSecret = "spa-bff-secret-that-is-at-least-thirty-two-chars";

    private readonly List<string> _databases = [];
    private Guid _readerRole;

    private Stack(Routes routes) => Routes = routes;

    public Routes Routes { get; }

    public WebApplication TokenServer { get; private set; } = null!;

    public WebApplication Management { get; private set; } = null!;

    public WebApplication Api { get; private set; } = null!;

    public WebApplication Bff { get; private set; } = null!;

    public LoadTenants Tenants { get; } = new();

    /// <summary>A client of any host (the routing handler picks the server by host name), without cookies.</summary>
    public HttpClient Client { get; private set; } = null!;

    public string ScimToken { get; private set; } = null!;

    public static async Task<Stack> StartAsync(StackOptions options)
    {
        var stack = new Stack(new Routes());
        await stack.StartTokenServerAsync(options);
        await stack.StartManagementAsync(options);
        await stack.StartApiAsync(options);
        await stack.StartBffAsync(options);
        stack.Client = new HttpClient(stack.Routes.Handler()) { BaseAddress = new Uri(Issuer) };
        stack.ScimToken = await stack.CreateScimTokenAsync();
        return stack;
    }

    private async Task<string> DatabaseAsync(string name)
    {
        var connectionString = TestDatabase.SqlServer
            ? await TestDatabase.CreateSqlServerAsync(name, CancellationToken.None)
            : new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(TestDatabase.SqliteFile(name)) { Pooling = true }.ToString();
        _databases.Add(connectionString);
        return connectionString;
    }

    private static WebApplicationBuilder Builder(StackOptions options)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        if (options.Logging)
        {
            // What a host logs with its default configuration (Information; ASP.NET Core at Warning), formatted and discarded.
            builder.Logging.SetMinimumLevel(LogLevel.Information);
            builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);
            if (options.RecommendedLogLevels)
            {
                // The levels docs/getting-started.md recommends (and the token server template sets).
                builder.Logging.AddFilter("OpenIddict", LogLevel.Warning);
                builder.Logging.AddFilter("Yarp", LogLevel.Warning);
            }

            builder.Logging.AddProvider(new FormattingLoggerProvider());
        }

        return builder;
    }

    private void RouteHttpClients(IServiceCollection services) =>
        services.PostConfigureAll<HttpClientFactoryOptions>(factory => factory.HttpMessageHandlerBuilderActions.Add(handler => handler.PrimaryHandler = Routes.Handler()));

    private async Task StartTokenServerAsync(StackOptions options)
    {
        var connectionString = await DatabaseAsync("load-auth");
        var enterprise = await DatabaseAsync("load-enterprise");
        var builder = Builder(options);
        var settings = new Dictionary<string, string?>
        {
            ["JeffOps:TokenServer:Issuer"] = Issuer,
            ["JeffOps:TokenServer:ApiScopes:api:0"] = "api",
            ["JeffOps:TokenServer:RefreshTokenReuseLeeway"] = "00:00:00",
            ["ConnectionStrings:authentication"] = connectionString,
            ["ConnectionStrings:enterprise"] = enterprise,
        };
        void Client(int index, string id, string secret, string[] grants, string[] scopes, string[]? permissions = null, string? redirect = null)
        {
            settings[$"JeffOps:TokenServer:Clients:{index}:ClientId"] = id;
            settings[$"JeffOps:TokenServer:Clients:{index}:ClientSecret"] = secret;
            for (var grant = 0; grant < grants.Length; grant++)
            {
                settings[$"JeffOps:TokenServer:Clients:{index}:GrantTypes:{grant}"] = grants[grant];
            }

            for (var scope = 0; scope < scopes.Length; scope++)
            {
                settings[$"JeffOps:TokenServer:Clients:{index}:Scopes:{scope}"] = scopes[scope];
            }

            for (var permission = 0; permission < (permissions?.Length ?? 0); permission++)
            {
                settings[$"JeffOps:TokenServer:Clients:{index}:ServicePermissions:{permission}"] = permissions![permission];
            }

            if (redirect is not null)
            {
                settings[$"JeffOps:TokenServer:Clients:{index}:RedirectUris:0"] = redirect;
            }
        }

        Client(0, BffClient, BffSecret, ["authorization_code", "refresh_token"], ["openid", "profile", "email", "offline_access", "api", "account"], redirect: BffRedirect);
        Client(1, LoadClient, LoadSecret, ["client_credentials"], ["api"], ["reports.read"]);
        Client(2, DpopClient, DpopSecret, ["client_credentials"], ["api"], ["orders.read"]);
        Client(3, ApiServiceClient, ApiServiceSecret, ["client_credentials"], ["api"], ["authorization.decisions.read"]);
        Client(4, SpaBffClient, SpaBffSecret, ["authorization_code", "refresh_token"], ["openid", "profile", "email", "offline_access", "api"], redirect: "https://bff.test/bff/callback");
        builder.Configuration.AddInMemoryCollection(settings);

        Tenants.Latency = options.DirectoryLatency;
        builder.Services.AddSingleton<ITenantDirectory>(Tenants);
        var authentication = builder.Services.AddJeffOpsAuthentication(builder.Configuration);
        var latency = new LatencyInterceptor(options.DatabaseLatency);
        if (TestDatabase.SqlServer)
        {
            authentication.AddSqlServerPersistence(migrateOnStartup: true);
        }
        else
        {
            authentication.UseDatabase((_, database) => database.UseSqlite(connectionString).AddInterceptors(latency));
        }

        var modules = new Application.DependencyInjection.AuthenticationBuilder(builder.Services, builder.Configuration);
        var scim = modules.AddEnterprise();
        if (TestDatabase.SqlServer)
        {
            scim.AddSqlServerPersistence(migrateOnStartup: true);
        }
        else
        {
            builder.Services.AddScoped<IEnterpriseDatabaseInitializer, CreateEnterprise>();
            scim.UseDatabase((_, database) => database.UseSqlite(enterprise));
        }

        builder.Services.AddScoped<IEnterpriseDatabaseInitializer, SeedDomain>();
        builder.Services.AddScoped<ITenantMembershipProvisioner, NoMemberships>();
        builder.Services.AddAuthentication().AddScheme<AuthenticationSchemeOptions, HeaderSignIn>("JeffOps.SignIn", _ => { });
        builder.Services.AddJeffOpsAuthenticationUI();
        builder.Services.AddAuthorizationBuilder()
            .AddPolicy("auth.enterprise.manage", policy => policy.RequireAuthenticatedUser())
            .AddPolicy("auth.enterprise.scim_tokens", policy => policy.RequireAuthenticatedUser());
        RouteHttpClients(builder.Services);

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
        app.MapJeffOpsEnterprise();
        app.MapJeffOpsScim();
        await app.StartAsync();
        TokenServer = app;
        Routes.Add("localhost", app.GetTestServer().CreateHandler());
    }

    private async Task StartManagementAsync(StackOptions options)
    {
        var connectionString = await DatabaseAsync("load-authz");
        var builder = Builder(options);
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:authorization"] = connectionString,
            ["JeffOps:Authorization:Cache:SealingKey"] = "load-test-sealing-key-management",
            ["JeffOps:Authentication:Authority"] = Issuer,
            ["JeffOps:Authentication:Audiences:0"] = "api",
        });
        builder.Services.AddSingleton<IPermissionCatalogProvider, Catalog>();
        builder.Services.AddSingleton<IBuiltInRoleProvider, Catalog>();
        builder.Services.AddJeffOpsAuthenticationClient(builder.Configuration);
        builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, jwt => jwt.BackchannelHttpHandler = Routes.Handler());
        builder.Services.AddJeffOpsPermissionAuthorization(builder.Configuration);
        var authorization = builder.Services.AddJeffOpsAuthorization(builder.Configuration);
        if (TestDatabase.SqlServer)
        {
            authorization.AddSqlServerPersistence(migrateOnStartup: true);
        }
        else
        {
            builder.Services.AddScoped<IAuthorizationDatabaseInitializer, CreateAuthorization>();
            authorization.UseDatabase((_, database) => database.UseSqlite(connectionString));
        }

        RouteHttpClients(builder.Services);
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapJeffOpsAuthorization();
        await app.StartAsync();
        Management = app;
        Routes.Add("mgmt.test", app.GetTestServer().CreateHandler());

        await using var scope = app.Services.CreateAsyncScope();
        _readerRole = await scope.ServiceProvider.GetRequiredService<AuthorizationDbContext>().Roles
            .Where(role => role.Name == Catalog.OrderReader).Select(role => role.Id).SingleAsync();
    }

    private async Task StartApiAsync(StackOptions options)
    {
        var builder = Builder(options);
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["JeffOps:Authentication:Authority"] = Issuer,
            ["JeffOps:Authentication:Audiences:0"] = "api",
            ["JeffOps:Authorization:ManagementBaseAddress"] = "https://mgmt.test/",
            ["JeffOps:Authorization:Cache:SealingKey"] = "load-test-sealing-key-orders-api",
            ["JeffOps:ServiceToken:TokenEndpoint"] = Issuer + "connect/token",
            ["JeffOps:ServiceToken:ClientId"] = ApiServiceClient,
            ["JeffOps:ServiceToken:ClientSecret"] = ApiServiceSecret,
            ["JeffOps:ServiceToken:Scope"] = "api",
        });
        builder.Services.AddJeffOpsAuthenticationClient(builder.Configuration);
        builder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, jwt => jwt.BackchannelHttpHandler = Routes.Handler());
        builder.Services.AddJeffOpsServiceTokens(builder.Configuration);
        builder.Services.AddJeffOpsPermissionAuthorization(builder.Configuration).ManagementClient.AddServiceToken();
        RouteHttpClients(builder.Services);
        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/api/orders", (ICurrentUser user) => new { orders = Array.Empty<int>(), user = user.UserId }).RequireAuthorization("orders.read");

        // No authentication, no authorization: the cost of the in-process plumbing alone, to subtract from the others.
        app.MapGet("/api/ping", () => new { orders = Array.Empty<int>(), user = (Guid?)null }).AllowAnonymous();
        await app.StartAsync();
        Api = app;
        Routes.Add("api.test", app.GetTestServer().CreateHandler());
    }

    private async Task StartBffAsync(StackOptions options)
    {
        var builder = Builder(options);
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["JeffOps:Bff:Authority"] = Issuer,
            ["JeffOps:Bff:ClientId"] = SpaBffClient,
            ["JeffOps:Bff:ClientSecret"] = SpaBffSecret,
            ["JeffOps:Bff:Scopes:0"] = "profile",
            ["JeffOps:Bff:Scopes:1"] = "email",
            ["JeffOps:Bff:Scopes:2"] = "api",
        });
        builder.Services.AddJeffOpsBff(builder.Configuration);
        RouteHttpClients(builder.Services);
        builder.Services.AddReverseProxy()
            .LoadFromMemory(
                [new RouteConfig { RouteId = "api", ClusterId = "api", Match = new RouteMatch { Path = "/api/{**rest}" } }],
                [new ClusterConfig { ClusterId = "api", Destinations = new Dictionary<string, DestinationConfig> { ["api"] = new() { Address = "https://api.test/" } } }])
            .AddBffTransforms();
        builder.Services.AddSingleton<IForwarderHttpClientFactory>(new RoutedForwarderFactory(Routes));
        var app = builder.Build();
        app.UseJeffOpsBff();
        app.MapJeffOpsBff();
        app.MapReverseProxy();
        await app.StartAsync();
        Bff = app;
        Routes.Add("bff.test", app.GetTestServer().CreateHandler());
    }

    // ---- Database growth ----------------------------------------------------------------------------------------------

    /// <summary>Rows in the token server's tables that grow with traffic, to see what a run leaves behind.</summary>
    public async Task<IReadOnlyDictionary<string, long>> RowCountsAsync()
    {
        await using var scope = TokenServer.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>();
        return new Dictionary<string, long>(StringComparer.Ordinal)
        {
            ["tokens"] = await db.Set<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreToken>().LongCountAsync(),
            ["authorizations"] = await db.Set<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreAuthorization>().LongCountAsync(),
            ["replay"] = await db.ReplayEntries.LongCountAsync(),
            ["ended-sessions"] = await db.EndedSessions.LongCountAsync(),
        };
    }

    /// <summary>
    /// One pruning pass with every spent token eligible (as the store maintenance does once they pass their retention), timed:
    /// what a pass costs on the rows a run left behind.
    /// </summary>
    public async Task<(long Tokens, long Authorizations, TimeSpan Elapsed)> PruneSpentAsync()
    {
        await using var scope = TokenServer.Services.CreateAsyncScope();
        var threshold = DateTimeOffset.UtcNow.AddDays(1);
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var tokens = await scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictTokenManager>().PruneAsync(threshold);
        var authorizations = await scope.ServiceProvider.GetRequiredService<OpenIddict.Abstractions.IOpenIddictAuthorizationManager>().PruneAsync(threshold);
        return (tokens, authorizations, clock.Elapsed);
    }

    // ---- Users and sessions --------------------------------------------------------------------------------------------

    /// <summary>A user of the tenant with the order reader role (so the API allows them), signed in nowhere yet.</summary>
    public async Task<Guid> CreateUserAsync(string email)
    {
        Guid accountId;
        await using (var scope = TokenServer.Services.CreateAsyncScope())
        {
            var account = Account.Register(email, "Load User", emailVerified: true, TimeProvider.System.GetUtcNow());
            scope.ServiceProvider.GetRequiredService<IAccountRepository>().Add(account);
            await scope.ServiceProvider.GetRequiredService<Application.Abstractions.IUnitOfWork>().SaveChangesAsync(CancellationToken.None);
            accountId = account.Id;
        }

        Tenants.Join(accountId);
        await using (var scope = Management.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthorizationDbContext>();
            db.Assignments.Add(Assignment.Grant(accountId, _readerRole, Tenant, "tenant", null, null, null, TimeProvider.System.GetUtcNow()));
            await db.SaveChangesAsync();
        }

        return accountId;
    }

    /// <summary>The authorization code flow with PKCE for <paramref name="accountId"/>, signed in through the header.</summary>
    public async Task<JsonElement> SignInAsync(Guid accountId)
    {
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        using var authorize = new HttpRequestMessage(HttpMethod.Get,
            $"connect/authorize?client_id={BffClient}&response_type=code&redirect_uri={Uri.EscapeDataString(BffRedirect)}" +
            $"&scope={Uri.EscapeDataString("openid profile email offline_access api account")}&code_challenge={challenge}&code_challenge_method=S256&state=xyz");
        authorize.Headers.Add(HeaderSignIn.Header, $"{accountId}|pwd,mfa|{TimeProvider.System.GetUtcNow().ToUnixTimeSeconds()}");
        using var response = await Client.SendAsync(authorize);
        if (response.StatusCode != HttpStatusCode.Redirect || response.Headers.Location is null)
        {
            throw new InvalidOperationException($"authorize: {(int)response.StatusCode} {await response.Content.ReadAsStringAsync()}");
        }

        var code = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(response.Headers.Location.Query)["code"].ToString();
        return await TokenAsync(new()
        {
            ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = BffRedirect, ["code_verifier"] = verifier,
            ["client_id"] = BffClient, ["client_secret"] = BffSecret,
        });
    }

    public async Task<JsonElement> TokenAsync(Dictionary<string, string> form, string? dpopProof = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "connect/token") { Content = new FormUrlEncodedContent(form) };
        if (dpopProof is not null)
        {
            request.Headers.Add("DPoP", dpopProof);
        }

        using var response = await Client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        return response.IsSuccessStatusCode
            ? JsonDocument.Parse(body).RootElement.Clone()
            : throw new InvalidOperationException($"token: {(int)response.StatusCode} {body}");
    }

    /// <summary>A browser signed in at the BFF: its own cookie jar, ready to call the API through the BFF.</summary>
    public async Task<HttpClient> BrowserAsync(Guid accountId)
    {
        var browser = new HttpClient(new CookieJar { InnerHandler = Routes.Handler() }) { BaseAddress = new Uri("https://bff.test/") };
        using var login = await browser.GetAsync(new Uri("bff/login?returnUrl=/app", UriKind.Relative));
        using var authorize = new HttpRequestMessage(HttpMethod.Get, login.Headers.Location);
        authorize.Headers.Add(HeaderSignIn.Header, $"{accountId}|pwd,mfa|{TimeProvider.System.GetUtcNow().ToUnixTimeSeconds()}");
        using var code = await browser.SendAsync(authorize);
        using var callback = await browser.GetAsync(code.Headers.Location);
        return callback.StatusCode == HttpStatusCode.Redirect
            ? browser
            : throw new InvalidOperationException($"bff callback: {(int)callback.StatusCode} {await callback.Content.ReadAsStringAsync()}");
    }

    private async Task<string> CreateScimTokenAsync()
    {
        var admin = await CreateUserAsync($"scim-admin-{Guid.NewGuid():N}@contoso.com");
        // The token server's own APIs take only an account token: narrow a refresh to the account scope.
        var refreshToken = (await SignInAsync(admin)).GetProperty("refresh_token").GetString()!;
        var access = (await TokenAsync(new()
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = BffClient,
            ["client_secret"] = BffSecret,
            ["scope"] = "account",
        })).GetProperty("access_token").GetString()!;
        using var request = new HttpRequestMessage(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.ScimTokenRoutes)
        {
            Content = System.Net.Http.Json.JsonContent.Create(new { name = "load" }),
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", access);
        using var response = await Client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        return response.IsSuccessStatusCode
            ? JsonDocument.Parse(body).RootElement.GetProperty("token").GetString()!
            : throw new InvalidOperationException($"scim token: {(int)response.StatusCode} {body}");
    }

    public static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public async ValueTask DisposeAsync()
    {
        Client?.Dispose();
        foreach (var app in new[] { Bff, Api, Management, TokenServer })
        {
            if (app is not null)
            {
                await app.DisposeAsync();
            }
        }

        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        foreach (var database in _databases)
        {
            await TestDatabase.DeleteAsync(database);
        }
    }

    // ---- Plumbing ------------------------------------------------------------------------------------------------------

    private sealed class Catalog : IPermissionCatalogProvider, IBuiltInRoleProvider
    {
        public const string OrderReader = "Order reader";

        public IReadOnlyList<PermissionDefinition> Definitions { get; } = [new("orders.read", "Read orders", "orders")];

        public IReadOnlyList<BuiltInRole> Roles { get; } = [new(OrderReader, ["orders.read"])];
    }

    private sealed class CreateEnterprise(EnterpriseDbContext db) : IEnterpriseDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.EnsureCreatedAsync(cancellationToken);
    }

    private sealed class CreateAuthorization(AuthorizationDbContext db) : IAuthorizationDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.EnsureCreatedAsync(cancellationToken);
    }

    private sealed class SeedDomain(EnterpriseDbContext db) : IEnterpriseDatabaseInitializer
    {
        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            if (!await db.Domains.AnyAsync(cancellationToken))
            {
                var domain = Enterprise.Domain.TenantDomain.Claim(Tenant, "contoso.com", TimeProvider.System.GetUtcNow());
                domain.CheckTxtRecords([domain.ExpectedValue("v=")], "v=", TimeProvider.System.GetUtcNow());
                db.Domains.Add(domain);
                await db.SaveChangesAsync(cancellationToken);
            }
        }
    }

    private sealed class NoMemberships : ITenantMembershipProvisioner
    {
        public Task AddMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RemoveMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class RoutedForwarderFactory(Routes routes) : IForwarderHttpClientFactory
    {
        public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context) => new(routes.Handler());
    }

    private sealed class CookieJar : DelegatingHandler
    {
        private readonly CookieContainer _cookies = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var header = _cookies.GetCookieHeader(request.RequestUri!);
            if (!string.IsNullOrEmpty(header))
            {
                request.Headers.Add("Cookie", header);
            }

            var response = await base.SendAsync(request, cancellationToken);
            foreach (var setCookie in response.Headers.TryGetValues("Set-Cookie", out var values) ? values : [])
            {
                _cookies.SetCookies(request.RequestUri!, setCookie);
            }

            return response;
        }
    }
}

/// <summary>Sends each request to the in-process server for its host name.</summary>
internal sealed class Routes
{
    private readonly ConcurrentDictionary<string, HttpMessageHandler> _servers = new(StringComparer.OrdinalIgnoreCase);

    public void Add(string host, HttpMessageHandler handler) => _servers[host] = handler;

    public HttpMessageHandler Handler() => new Router(this);

    private sealed class Router(Routes routes) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            new HttpMessageInvoker(routes._servers[request.RequestUri!.Host], disposeHandler: false).SendAsync(request, cancellationToken);
    }
}

/// <summary>Every user is in the one tenant. <see cref="Latency"/> stands in for a slow host directory.</summary>
internal sealed class LoadTenants : ITenantDirectory
{
    private readonly ConcurrentDictionary<Guid, bool> _members = new();

    public TimeSpan Latency { get; set; }

    public void Join(Guid accountId) => _members[accountId] = true;

    public async Task<IReadOnlyList<TenantMembership>> GetMembershipsAsync(Guid accountId, CancellationToken cancellationToken)
    {
        if (Latency > TimeSpan.Zero)
        {
            await Task.Delay(Latency, cancellationToken);
        }

        return _members.ContainsKey(accountId) ? [new TenantMembership(Stack.Tenant, null, null, AccessLevel.Tenant)] : [];
    }

    public Task<TenantInfo?> FindTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        Task.FromResult<TenantInfo?>(new TenantInfo(tenantId, null, true));
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

/// <summary>A database that answers every command <paramref name="latency"/> late (SQLite runs only).</summary>
internal sealed class LatencyInterceptor(TimeSpan latency) : DbCommandInterceptor
{
    public override async ValueTask<InterceptionResult<System.Data.Common.DbDataReader>> ReaderExecutingAsync(
        System.Data.Common.DbCommand command, CommandEventData eventData, InterceptionResult<System.Data.Common.DbDataReader> result, CancellationToken cancellationToken = default)
    {
        await DelayAsync(cancellationToken);
        return await base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
    }

    public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(
        System.Data.Common.DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        await DelayAsync(cancellationToken);
        return await base.NonQueryExecutingAsync(command, eventData, result, cancellationToken);
    }

    public override async ValueTask<InterceptionResult<object>> ScalarExecutingAsync(
        System.Data.Common.DbCommand command, CommandEventData eventData, InterceptionResult<object> result, CancellationToken cancellationToken = default)
    {
        await DelayAsync(cancellationToken);
        return await base.ScalarExecutingAsync(command, eventData, result, cancellationToken);
    }

    private Task DelayAsync(CancellationToken cancellationToken) => latency > TimeSpan.Zero ? Task.Delay(latency, cancellationToken) : Task.CompletedTask;
}

/// <summary>Formats every message it is given and throws it away: the cost of logging without the cost of the sink.</summary>
internal sealed class FormattingLoggerProvider : ILoggerProvider
{
    public static long Messages;

    /// <summary>Messages formatted per category (the first two dot-separated parts), to see where log volume comes from.</summary>
    public static readonly ConcurrentDictionary<string, long> ByCategory = new(StringComparer.Ordinal);

    public ILogger CreateLogger(string categoryName) => new Logger(string.Join('.', categoryName.Split('.').Take(3)));

    public void Dispose()
    {
    }

    private sealed class Logger(string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            _ = formatter(state, exception);
            Interlocked.Increment(ref Messages);
            ByCategory.AddOrUpdate(category, 1, (_, count) => count + 1);
        }
    }
}

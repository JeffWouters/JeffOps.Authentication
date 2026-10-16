using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Encodings.Web;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.AspNetCore.DependencyInjection;
using JeffOps.Authorization.Domain.Permissions;
using JeffOps.Authorization.Endpoints;
using JeffOps.Authorization.Infrastructure.DependencyInjection;
using JeffOps.Authorization.Infrastructure.Persistence;
using JeffOps.Authorization.Persistence.SqlServer;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace JeffOps.Authorization.Management.Tests;

/// <summary>
/// The management service as a host would run it: SQLite on disk, built-in roles and a host catalog, permission
/// authorization co-hosted on the same store, and a test scheme that signs in whichever principal a test registered.
/// </summary>
internal sealed class ManagementHost : IAsyncDisposable
{
    public static readonly Guid TenantA = Guid.Parse("aaaaaaaa-0000-4000-8000-000000000001");
    public static readonly Guid TenantB = Guid.Parse("bbbbbbbb-0000-4000-8000-000000000002");
    public static readonly Guid Root = Guid.Parse("00000000-0000-4000-8000-0000000000ff");

    public const string TenantAdmin = "Tenant admin";
    public const string BreakGlass = "Break glass";

    private readonly WebApplication _app;
    private readonly string _connectionString;

    private ManagementHost(WebApplication app, string connectionString, FakeTimeProvider time)
    {
        _app = app;
        _connectionString = connectionString;
        Time = time;
        Client = app.GetTestClient();
    }

    public HttpClient Client { get; }

    public FakeTimeProvider Time { get; }

    public IServiceProvider Services => _app.Services;

    public static async Task<ManagementHost> StartAsync(Dictionary<string, string?>? overrides = null)
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var connectionString = TestDatabase.SqlServer
            ? await TestDatabase.CreateSqlServerAsync("authz", TestContext.Current.CancellationToken)
            : TestDatabase.SqliteFile("authz");
        try
        {
            return await StartAsync(connectionString, time, overrides);
        }
        catch
        {
            await TestDatabase.DeleteAsync(connectionString);
            throw;
        }
    }

    private static async Task<ManagementHost> StartAsync(string connectionString, FakeTimeProvider time, Dictionary<string, string?>? overrides)
    {

        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        var settings = new Dictionary<string, string?>
        {
            ["JeffOps:Authorization:Cache:SealingKey"] = "test-sealing-key",
        };
        foreach (var (key, value) in overrides ?? [])
        {
            settings[key] = value;
        }

        builder.Configuration.AddInMemoryCollection(settings);
        builder.Configuration["ConnectionStrings:authorization"] = connectionString;

        builder.Services.AddSingleton<TimeProvider>(time);
        builder.Services.AddSingleton<IPermissionCatalogProvider, TestCatalog>();
        builder.Services.AddSingleton<IBuiltInRoleProvider, TestCatalog>();
        builder.Services.AddJeffOpsPermissionAuthorization(builder.Configuration);
        var authorization = builder.Services.AddJeffOpsAuthorization(builder.Configuration);
        if (TestDatabase.SqlServer)
        {
            authorization.AddSqlServerPersistence(migrateOnStartup: true);
        }
        else
        {
            builder.Services.AddScoped<IAuthorizationDatabaseInitializer, CreateDatabase>();
            authorization.UseDatabase((_, options) => options.UseSqlite(connectionString));
        }
        builder.Services.AddAuthentication(TestAuthentication.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, TestAuthentication>(TestAuthentication.SchemeName, _ => { });

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapJeffOpsAuthorization();
        app.MapGet("/invoices", () => "ok").RequireAuthorization("billing.invoices.read");
        await app.StartAsync(TestContext.Current.CancellationToken);

        return new ManagementHost(app, connectionString, time);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.DisposeAsync();
        await TestDatabase.DeleteAsync(_connectionString);
    }

    // ---- Callers -------------------------------------------------------------------------------------------------------

    public static ClaimsPrincipal RootUser() =>
        Principal(("sub", Root.ToString()), ("tid", TenantA.ToString()), ("lvl", "Root"), ("step_up", "mfa"));

    public static ClaimsPrincipal User(Guid userId, Guid? tenantId = null, bool steppedUp = true, params (string Type, string Value)[] extra)
    {
        List<(string, string)> claims = [("sub", userId.ToString()), ("tid", (tenantId ?? TenantA).ToString())];
        if (steppedUp)
        {
            claims.Add(("step_up", "mfa"));
        }

        return Principal([.. claims, .. extra]);
    }

    public static ClaimsPrincipal Service(string name, params string[] permissions) =>
        Principal([("sub", name), ("lvl", "Service"), .. permissions.Select(permission => ("perm", permission))]);

    public static ClaimsPrincipal Principal(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(claim => new Claim(claim.Type, claim.Value)), TestAuthentication.SchemeName));

    // ---- Requests ------------------------------------------------------------------------------------------------------

    public Task<HttpResponseMessage> GetAsync(ClaimsPrincipal user, string path) => SendAsync(user, HttpMethod.Get, path);

    public Task<HttpResponseMessage> SendAsync(ClaimsPrincipal user, HttpMethod method, string path, object? body = null)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue(TestAuthentication.SchemeName, TestAuthentication.Register(user));
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, body.GetType());
        }

        return Client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    public async Task<T> ReadAsync<T>(HttpResponseMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);
        return (await response.Content.ReadFromJsonAsync<T>(TestContext.Current.CancellationToken))!;
    }

    public static async Task<string?> CodeOf(HttpResponseMessage response)
    {
        ArgumentNullException.ThrowIfNull(response);
        var problem = await response.Content.ReadFromJsonAsync<Dictionary<string, object?>>(TestContext.Current.CancellationToken);
        return problem?.GetValueOrDefault("code")?.ToString();
    }

    private sealed class CreateDatabase(AuthorizationDbContext db) : IAuthorizationDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.EnsureCreatedAsync(cancellationToken);
    }
}

/// <summary>The host's static catalog and built-in roles.</summary>
internal sealed class TestCatalog : IPermissionCatalogProvider, IBuiltInRoleProvider
{
    public IReadOnlyList<PermissionDefinition> Definitions { get; } =
    [
        new("billing.invoices.read", "Read invoices", "billing"),
        new("billing.invoices.write", "Write invoices", "billing"),
    ];

    public IReadOnlyList<BuiltInRole> Roles { get; } =
    [
        new(ManagementHost.TenantAdmin,
        [
            "authorization.roles.read", "authorization.roles.write", "authorization.assignments.read", "authorization.assignments.write",
            "billing.invoices.read",
        ]),
        new(ManagementHost.BreakGlass, ["billing.invoices.read"]) { IsBreakGlass = true },
    ];
}

/// <summary>Signs in the principal a test registered under the token in the Authorization header.</summary>
internal sealed class TestAuthentication(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Test";

    private static readonly ConcurrentDictionary<string, ClaimsPrincipal> Principals = new();

    public static string Register(ClaimsPrincipal user)
    {
        var token = Guid.NewGuid().ToString("N");
        Principals[token] = user;
        return token;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (!header.StartsWith(SchemeName + " ", StringComparison.Ordinal)
            || !Principals.TryGetValue(header[(SchemeName.Length + 1)..], out var user))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(user, SchemeName)));
    }
}

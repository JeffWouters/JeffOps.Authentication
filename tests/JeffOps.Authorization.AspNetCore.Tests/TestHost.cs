using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using JeffOps.Authorization.AspNetCore.Data;
using JeffOps.Authorization.AspNetCore.DependencyInjection;
using JeffOps.Authorization.Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using JeffOps.Authorization.AspNetCore.Evaluation;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JeffOps.Authorization.AspNetCore.Tests;

/// <summary>
/// A real ASP.NET Core host on TestServer with permission authorization wired exactly as a resource service would, an
/// in-memory data source, and an authentication scheme that signs in whichever principal a test registered.
/// </summary>
internal sealed class TestApp : IAsyncDisposable
{
    public static readonly Guid TenantId = Guid.Parse("7a0c0de0-0000-4000-8000-0000000000aa");

    private readonly WebApplication _app;

    private TestApp(WebApplication app, FakeDataSource data)
    {
        _app = app;
        Data = data;
        Client = app.GetTestClient();
    }

    public FakeDataSource Data { get; }

    public HttpClient Client { get; }

    public IServiceProvider Services => _app.Services;

    public static async Task<TestApp> StartAsync(
        Action<WebApplication>? mapEndpoints = null,
        Dictionary<string, string?>? settings = null,
        FakeDataSource? data = null)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(settings ?? new Dictionary<string, string?>
        {
            ["JeffOps:Authorization:SensitivePermissions:0"] = "policy.write",
            ["JeffOps:Authorization:ImpersonationRefusedPermissions:0"] = "roles.assignments.write",
            ["JeffOps:Authorization:Cache:SealingKey"] = "test-sealing-key",
        });

        data ??= new FakeDataSource();
        builder.Services.AddSingleton(data);
        builder.Services.AddJeffOpsPermissionAuthorization(builder.Configuration);
        builder.Services.AddTransient<IAuthorizationDataSource>(provider => provider.GetRequiredService<FakeDataSource>());
        builder.Services.AddAuthentication(TestAuthentication.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, TestAuthentication>(TestAuthentication.SchemeName, _ => { });

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        (mapEndpoints ?? MapDefaultEndpoints)(app);
        await app.StartAsync(TestContext.Current.CancellationToken);

        return new TestApp(app, data);
    }

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _app.DisposeAsync();
    }

    /// <summary>A request authenticated as <paramref name="user"/>.</summary>
    public static HttpRequestMessage As(ClaimsPrincipal user, HttpMethod method, string path)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue(TestAuthentication.SchemeName, TestAuthentication.Register(user));
        return request;
    }

    public static ClaimsPrincipal User(Guid userId, params (string Type, string Value)[] extra) =>
        Principal([("sub", userId.ToString()), ("tid", TenantId.ToString()), .. extra]);

    public static ClaimsPrincipal Principal(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(claim => new Claim(claim.Type, claim.Value)), TestAuthentication.SchemeName));

    private static void MapDefaultEndpoints(WebApplication app)
    {
        app.MapGet("/findings", () => "ok").RequireAuthorization("findings.read");
        app.MapPost("/findings", () => "ok").RequireAuthorization("findings.write");
        app.MapPost("/policies", () => "ok").RequireAuthorization("policy.write");
        app.MapPost("/policies/preview", () => "ok").RequireAuthorization("policy.write").AllowWithoutStepUp("policy.write");
        app.MapGet("/assignments", () => "ok").RequireAuthorization("roles.assignments.write");
        app.MapPost("/assignments", () => "ok").RequireAuthorization("roles.assignments.write");
        app.MapPost("/lockbox", () => "ok").RequireAuthorization("findings.write").RefuseUnderImpersonation();
        app.MapGet("/workspaces/{workspaceId}/items", () => "ok").RequirePermission("items.read", "workspace", "workspaceId");
    }
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

/// <summary>In-memory authorization data; counts reads so tests can see the cache at work.</summary>
internal sealed class FakeDataSource : IAuthorizationDataSource
{
    public static readonly Guid Reader = Guid.Parse("5e1f0000-0000-4000-8000-000000000001");
    public static readonly Guid Writer = Guid.Parse("5e1f0000-0000-4000-8000-000000000002");
    public static readonly Guid Admin = Guid.Parse("5e1f0000-0000-4000-8000-000000000003");
    public static readonly Guid ItemReader = Guid.Parse("5e1f0000-0000-4000-8000-000000000004");

    private int _assignmentReads;

    public ConcurrentDictionary<(Guid User, Guid Tenant), List<UserAssignmentDto>> Assignments { get; } = new();

    public Dictionary<Guid, string[]> RolePermissions { get; } = new()
    {
        [Reader] = ["findings.read"],
        [Writer] = ["findings.*"],
        [Admin] = ["policy.write", "roles.assignments.write", "findings.*"],
        [ItemReader] = ["items.read"],
    };

    public List<AttributePolicyDto> Policies { get; } = [];

    public List<ScopeDto> Scopes { get; } =
    [
        new("system", "System", null, null, true),
        new("organization", "Organization", null, "system", false),
        new("tenant", "Tenant", null, "organization", false),
        new("workspace", "Workspace", null, "tenant", false),
    ];

    public int AssignmentReads => Volatile.Read(ref _assignmentReads);

    public void Assign(Guid userId, Guid roleId, string scope = "tenant", Guid? instance = null, DateTimeOffset? expiresAt = null) =>
        Assignments.GetOrAdd((userId, TestApp.TenantId), _ => []).Add(new UserAssignmentDto(roleId, scope, instance, expiresAt));

    public Task<IReadOnlyList<UserAssignmentDto>> GetUserAssignmentsAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _assignmentReads);
        return Task.FromResult<IReadOnlyList<UserAssignmentDto>>(
            Assignments.TryGetValue((userId, tenantId), out var list) ? [.. list] : []);
    }

    public Task<IReadOnlyDictionary<Guid, string[]>> GetRolePermissionsAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyDictionary<Guid, string[]>>(RolePermissions);

    public Task<IReadOnlyList<AttributePolicyDto>> GetPoliciesAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<AttributePolicyDto>>([.. Policies]);

    public Task<IReadOnlyList<ScopeDto>> GetScopesAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<ScopeDto>>([.. Scopes]);
}

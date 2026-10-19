using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Client.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace JeffOps.Authentication.Client.Tests;

public sealed class JwtValidationTests
{
    private const string Issuer = "https://issuer.test";
    private static readonly RsaSecurityKey SigningKey = new(RSA.Create(2048)) { KeyId = "test-key" };

    private static string Token(string? audience, params (string Type, string Value)[] claims) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = audience,
            Subject = new ClaimsIdentity(claims.Select(claim => new Claim(claim.Type, claim.Value))),
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.RsaSha256),
        });

    private static async Task<WebApplication> StartAsync(string environment = "Production", Dictionary<string, string?>? settings = null)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = environment });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(settings ?? new Dictionary<string, string?>
        {
            ["JeffOps:Authentication:Authority"] = Issuer,
            ["JeffOps:Authentication:Audiences:0"] = "api",
            ["JeffOps:Authentication:Audiences:1"] = "svc-reports",
        });

        builder.Services.AddJeffOpsAuthenticationClient(builder.Configuration);

        // Use the local signing key instead of fetching discovery metadata from the authority.
        builder.Services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options =>
        {
            var configuration = new OpenIdConnectConfiguration { Issuer = Issuer };
            configuration.SigningKeys.Add(SigningKey);
            options.Configuration = configuration;
            options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
        });

        var app = builder.Build();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/me", (ICurrentUser user) => user.UserId?.ToString() ?? "none");
        app.MapGet("/public", () => "hello").AllowAnonymous();
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<HttpResponseMessage> GetAsync(WebApplication app, string path, string? token = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        return await app.GetTestClient().SendAsync(request, TestContext.Current.CancellationToken);
    }

    [Theory]
    [InlineData("api")]
    [InlineData("svc-reports")]
    public async Task A_token_for_an_accepted_audience_is_valid(string audience)
    {
        await using var app = await StartAsync();
        var userId = Guid.NewGuid();

        var response = await GetAsync(app, "/me", Token(audience, ("sub", userId.ToString())));

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).ShouldBe(userId.ToString(), "sub is read raw, not mapped");
    }

    [Theory]
    [InlineData("svc-other")]
    [InlineData(null)]
    public async Task A_token_for_another_or_no_audience_is_rejected(string? audience)
    {
        await using var app = await StartAsync();

        (await GetAsync(app, "/me", Token(audience, ("sub", Guid.NewGuid().ToString())))).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Every_endpoint_requires_authentication_unless_it_opts_out()
    {
        await using var app = await StartAsync();

        (await GetAsync(app, "/me")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await GetAsync(app, "/public")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_service_principal_has_no_user_id()
    {
        await using var app = await StartAsync();

        var response = await GetAsync(app, "/me", Token("api", ("sub", "svc-reports"), ("lvl", "Service")));

        (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).ShouldBe("none");
    }

    [Theory]
    [InlineData("Production", true)]
    [InlineData("Staging", true)]
    [InlineData("Development", false)]
    public async Task Https_metadata_is_required_outside_development(string environment, bool required)
    {
        await using var app = await StartAsync(environment);

        var options = app.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);

        options.RequireHttpsMetadata.ShouldBe(required);
        options.MapInboundClaims.ShouldBeFalse();
        options.TokenValidationParameters.ValidateAudience.ShouldBeTrue();
    }

    [Fact]
    public async Task Missing_authority_or_audiences_fail_startup()
    {
        await Should.ThrowAsync<OptionsValidationException>(() => StartAsync(settings: new Dictionary<string, string?>
        {
            ["JeffOps:Authentication:Audiences:0"] = "api",
        }));

        await Should.ThrowAsync<OptionsValidationException>(() => StartAsync(settings: new Dictionary<string, string?>
        {
            ["JeffOps:Authentication:Authority"] = Issuer,
        }));
    }
}

public sealed class AccessContextTests
{
    private static readonly Guid HomeTenant = Guid.NewGuid();
    private static readonly Guid HeaderTenant = Guid.NewGuid();

    private static async Task<AccessContext> ResolveAsync(ClaimsPrincipal user, bool trustService = false)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<Microsoft.Extensions.Hosting.IHostEnvironment>(new TestEnvironment());
        services.AddJeffOpsAuthenticationClient(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["JeffOps:Authentication:Authority"] = "https://issuer.test",
            ["JeffOps:Authentication:Audiences:0"] = "api",
            ["JeffOps:Authentication:ServiceTokenTenantScoping:TrustForServiceTokens"] = trustService.ToString(),
        }).Build());

        await using var provider = services.BuildServiceProvider();
        var http = new DefaultHttpContext { User = user };
        http.Request.Headers["X-Tenant-Id"] = HeaderTenant.ToString();
        provider.GetRequiredService<IHttpContextAccessor>().HttpContext = http;

        await using var scope = provider.CreateAsyncScope();
        return scope.ServiceProvider.GetRequiredService<IAccessContextAccessor>().GetAccessContext();
    }

    private static ClaimsPrincipal Principal(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(claim => new Claim(claim.Type, claim.Value)), "test"));

    [Fact]
    public async Task Claims_become_the_access_context()
    {
        var user = Guid.NewGuid();
        var acting = Guid.NewGuid();

        var context = await ResolveAsync(Principal(("sub", user.ToString()), ("tid", HomeTenant.ToString()), ("lvl", "Delegated"), ("act_tid", acting.ToString())));

        context.UserId.ShouldBe(user);
        context.Level.ShouldBe(AccessLevel.Delegated);
        context.EffectiveTenantId.ShouldBe(acting);
    }

    [Fact]
    public async Task Tenant_headers_are_ignored_by_default() =>
        (await ResolveAsync(Principal(("sub", "svc-reports"), ("lvl", "Service")))).EffectiveTenantId.ShouldBeNull();

    [Fact]
    public async Task A_service_token_is_scoped_by_the_header_when_enabled() =>
        (await ResolveAsync(Principal(("sub", "svc-reports"), ("lvl", "Service")), trustService: true)).EffectiveTenantId.ShouldBe(HeaderTenant);

    [Fact]
    public async Task A_platform_administrator_is_never_scoped_by_headers()
    {
        // Root comes only from a person's membership; acting in a tenant goes through the audited tenant switch.
        var root = Principal(("sub", Guid.NewGuid().ToString()), ("lvl", "Root"));

        (await ResolveAsync(root, trustService: true)).EffectiveTenantId.ShouldBeNull();
    }

    [Fact]
    public async Task A_user_token_is_never_scoped_by_headers()
    {
        var context = await ResolveAsync(
            Principal(("sub", Guid.NewGuid().ToString()), ("tid", HomeTenant.ToString())),
            trustService: true);

        context.EffectiveTenantId.ShouldBe(HomeTenant);
    }

    private sealed class TestEnvironment : Microsoft.Extensions.Hosting.IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Production";

        public string ApplicationName { get; set; } = "tests";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } =
            new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
}

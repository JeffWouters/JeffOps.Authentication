using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Dpop;
using JeffOps.Authentication.Client.Access;
using JeffOps.Authentication.Client.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace JeffOps.Authentication.Client.Tests;

public sealed class DpopProofValidatorTests
{
    private static readonly Uri Target = new("https://api.test/things");

    [Fact]
    public void A_valid_proof_yields_the_key_thumbprint()
    {
        using var key = new DpopKey();

        var (proof, error) = DpopProofValidator.Validate(key.Proof("GET", "https://api.test/things?page=2"), "GET", Target, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5));

        error.ShouldBeNull();
        proof!.Jkt.ShouldBe(key.Thumbprint);
    }

    [Fact]
    public void Proofs_for_another_request_time_or_token_are_refused()
    {
        using var key = new DpopKey();
        var now = DateTimeOffset.UtcNow;

        DpopProofValidator.Validate(key.Proof("POST", Target.AbsoluteUri), "GET", Target, now, TimeSpan.FromMinutes(5)).Error.ShouldNotBeNull();
        DpopProofValidator.Validate(key.Proof("GET", "https://api.test/other"), "GET", Target, now, TimeSpan.FromMinutes(5)).Error.ShouldNotBeNull();
        DpopProofValidator.Validate(key.Proof("GET", Target.AbsoluteUri, issuedAt: now.AddMinutes(-10)), "GET", Target, now, TimeSpan.FromMinutes(5)).Error.ShouldNotBeNull();
        DpopProofValidator.Validate(key.Proof("GET", Target.AbsoluteUri, accessToken: "a"), "GET", Target, now, TimeSpan.FromMinutes(5), accessToken: "b").Error.ShouldNotBeNull();
        DpopProofValidator.Validate(key.Proof("GET", Target.AbsoluteUri, typ: "JWT"), "GET", Target, now, TimeSpan.FromMinutes(5)).Error.ShouldNotBeNull();
    }

    [Fact]
    public void A_proof_signed_by_another_key_than_its_jwk_is_refused()
    {
        using var key = new DpopKey();
        using var other = new DpopKey();

        var forged = key.Proof("GET", Target.AbsoluteUri, jwkOverride: other.PublicJwk);

        DpopProofValidator.Validate(forged, "GET", Target, DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5)).Error.ShouldNotBeNull();
    }

    [Fact]
    public void Thumbprints_follow_rfc_7638()
    {
        // RFC 7638 section 3.1.
        var jwk = JsonSerializer.SerializeToElement(new
        {
            kty = "RSA",
            n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            e = "AQAB",
            alg = "RS256",
            kid = "2011-04-29",
        });

        DpopProofValidator.Thumbprint(jwk).ShouldBe("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }
}

public sealed class DpopResourceServerTests
{
    private const string Issuer = "https://issuer.test";
    private static readonly RsaSecurityKey SigningKey = new(RSA.Create(2048)) { KeyId = "dpop-test-key" };

    [Fact]
    public void Configurations_that_would_skip_the_dpop_checks_are_refused()
    {
        Action<JwtBearerOptions>[] unsafeSettings = [jwt => jwt.EventsType = typeof(JwtBearerEvents), jwt => jwt.UseSecurityTokenValidators = true];
        foreach (var unsafeSetting in unsafeSettings)
        {
            var services = new ServiceCollection();
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["JeffOps:Authentication:Authority"] = Issuer,
                ["JeffOps:Authentication:Audiences:0"] = "api",
            }).Build();
            services.AddSingleton<Microsoft.Extensions.Hosting.IHostEnvironment>(new Microsoft.Extensions.Hosting.Internal.HostingEnvironment { EnvironmentName = "Production" });
            services.AddJeffOpsAuthenticationClient(configuration);
            services.Configure(JwtBearerDefaults.AuthenticationScheme, unsafeSetting);
            using var provider = services.BuildServiceProvider();

            Should.Throw<InvalidOperationException>(() => provider.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme));
        }
    }

    [Fact]
    public async Task A_bound_token_needs_its_proof_and_the_dpop_scheme()
    {
        await using var app = await StartAsync();
        using var key = new DpopKey();
        var token = Token(key.Thumbprint);

        (await SendAsync(app, "Bearer", token)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        (await SendAsync(app, "DPoP", token)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        var proof = key.Proof("GET", "http://localhost/me", token);
        (await SendAsync(app, "DPoP", token, proof)).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await SendAsync(app, "DPoP", token, proof)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "a proof works once");

        using var thief = new DpopKey();
        (await SendAsync(app, "DPoP", token, thief.Proof("GET", "http://localhost/me", token))).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Required_mode_refuses_plain_bearer_tokens()
    {
        await using var allowed = await StartAsync();
        await using var required = await StartAsync(DpopMode.Required);
        var plain = Token(null);

        (await SendAsync(allowed, "Bearer", plain)).StatusCode.ShouldBe(HttpStatusCode.OK);
        var refused = await SendAsync(required, "Bearer", plain);
        refused.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        refused.Headers.WwwAuthenticate.ToString().ShouldContain("DPoP");
    }

    private static string Token(string? jkt)
    {
        var claims = new Dictionary<string, object> { ["sub"] = Guid.NewGuid().ToString() };
        if (jkt is not null)
        {
            claims["cnf"] = new Dictionary<string, object> { ["jkt"] = jkt };
        }

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = "api",
            Claims = claims,
            Expires = DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.RsaSha256),
        });
    }

    private static async Task<WebApplication> StartAsync(DpopMode mode = DpopMode.Allowed)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Production" });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["JeffOps:Authentication:Authority"] = Issuer,
            ["JeffOps:Authentication:Audiences:0"] = "api",
            ["JeffOps:Authentication:Dpop"] = mode.ToString(),
        });
        builder.Services.AddJeffOpsAuthenticationClient(builder.Configuration);
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
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    private static async Task<HttpResponseMessage> SendAsync(WebApplication app, string scheme, string token, string? proof = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/me");
        request.Headers.Authorization = new AuthenticationHeaderValue(scheme, token);
        if (proof is not null)
        {
            request.Headers.Add("DPoP", proof);
        }

        return await app.GetTestClient().SendAsync(request, TestContext.Current.CancellationToken);
    }
}

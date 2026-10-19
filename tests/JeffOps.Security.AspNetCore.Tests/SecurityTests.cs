using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JeffOps.Security.AspNetCore.Tests;

internal static class Host
{
    public static async Task<WebApplication> StartAsync(
        Dictionary<string, string?> settings,
        string environment = "Production",
        Action<WebApplicationBuilder>? configure = null)
    {
        var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = environment });
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(settings);
        builder.Services.AddJeffOpsSecurity(builder.Configuration);
        configure?.Invoke(builder);

        var app = builder.Build();
        app.UseJeffOpsSecurity();
        app.MapGet("/", () => "ok");
        app.MapGet("/health", () => "healthy");
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    public static readonly Dictionary<string, string?> NoProxy = new() { ["JeffOps:ForwardedHeaders:NoTrustedProxy"] = "true" };

    public static Dictionary<string, string?> With(this Dictionary<string, string?> settings, string key, string? value) =>
        new(settings) { [key] = value };
}

public sealed class SecurityHeaderTests
{
    [Fact]
    public async Task Responses_carry_the_security_headers()
    {
        await using var app = await Host.StartAsync(Host.NoProxy);

        var response = await app.GetTestClient().GetAsync(new Uri("/", UriKind.Relative), TestContext.Current.CancellationToken);

        response.Headers.GetValues("X-Content-Type-Options").ShouldBe(["nosniff"]);
        response.Headers.GetValues("X-Frame-Options").ShouldBe(["DENY"]);
        response.Headers.GetValues("Referrer-Policy").ShouldBe(["no-referrer"]);
        response.Headers.GetValues("Content-Security-Policy").ShouldBe(["default-src 'none'; frame-ancestors 'none'"]);
        response.Headers.Contains("Strict-Transport-Security").ShouldBeFalse("HSTS is sent over HTTPS only");
    }

    [Fact]
    public async Task Https_responses_carry_hsts()
    {
        await using var app = await Host.StartAsync(Host.NoProxy);
        using var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://localhost/");

        var response = await client.GetAsync(new Uri("/", UriKind.Relative), TestContext.Current.CancellationToken);

        response.Headers.GetValues("Strict-Transport-Security").ShouldBe(["max-age=31536000; includeSubDomains"]);
    }

    [Fact]
    public async Task The_content_security_policy_is_configurable()
    {
        await using var app = await Host.StartAsync(Host.NoProxy.With("JeffOps:SecurityHeaders:ContentSecurityPolicy", "default-src 'self'"));

        var response = await app.GetTestClient().GetAsync(new Uri("/", UriKind.Relative), TestContext.Current.CancellationToken);

        response.Headers.GetValues("Content-Security-Policy").ShouldBe(["default-src 'self'"]);
    }
}

public sealed class CorsTests
{
    private static async Task<HttpResponseMessage> PreflightAsync(WebApplication app, string origin)
    {
        using var request = new HttpRequestMessage(HttpMethod.Options, "/");
        request.Headers.Add("Origin", origin);
        request.Headers.Add("Access-Control-Request-Method", "POST");
        return await app.GetTestClient().SendAsync(request, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task A_configured_origin_is_allowed_with_credentials()
    {
        await using var app = await Host.StartAsync(Host.NoProxy.With("JeffOps:Cors:AllowedOrigins:0", "https://app.example"));

        var response = await PreflightAsync(app, "https://app.example");

        response.Headers.GetValues("Access-Control-Allow-Origin").ShouldBe(["https://app.example"]);
        response.Headers.GetValues("Access-Control-Allow-Credentials").ShouldBe(["true"]);
    }

    [Fact]
    public async Task Other_origins_are_refused()
    {
        await using var app = await Host.StartAsync(Host.NoProxy.With("JeffOps:Cors:AllowedOrigins:0", "https://app.example"));

        (await PreflightAsync(app, "https://evil.example")).Headers.Contains("Access-Control-Allow-Origin").ShouldBeFalse();
    }

    [Fact]
    public async Task Without_configuration_no_origin_is_allowed()
    {
        await using var app = await Host.StartAsync(Host.NoProxy);

        (await PreflightAsync(app, "https://app.example")).Headers.Contains("Access-Control-Allow-Origin").ShouldBeFalse();
    }
}

public sealed class ForwardedHeadersTests
{
    [Fact]
    public async Task Outside_development_an_unacknowledged_missing_proxy_configuration_fails_startup() =>
        await Should.ThrowAsync<OptionsValidationException>(() => Host.StartAsync([]));

    [Fact]
    public async Task Development_does_not_require_proxy_configuration()
    {
        await using var app = await Host.StartAsync([], environment: "Development");
    }

    [Fact]
    public async Task Invalid_proxy_addresses_fail_startup() =>
        await Should.ThrowAsync<OptionsValidationException>(() => Host.StartAsync(new Dictionary<string, string?>
        {
            ["JeffOps:ForwardedHeaders:TrustedProxyHops"] = "1",
            ["JeffOps:ForwardedHeaders:KnownProxies:0"] = "not-an-ip",
        }));

    [Fact]
    public async Task Outside_development_trusted_hops_need_the_proxies_listed() =>
        (await Should.ThrowAsync<OptionsValidationException>(() => Host.StartAsync(new Dictionary<string, string?>
        {
            ["JeffOps:ForwardedHeaders:TrustedProxyHops"] = "1",
        }))).Message.ShouldContain("KnownProxies");

    [Theory]
    [InlineData("JeffOps:ForwardedHeaders:KnownProxies:0", "10.0.0.5")]
    [InlineData("JeffOps:ForwardedHeaders:KnownNetworks:0", "10.0.0.0/8")]
    public async Task Listed_proxies_satisfy_trusted_hops(string key, string value)
    {
        await using var app = await Host.StartAsync(new Dictionary<string, string?>
        {
            ["JeffOps:ForwardedHeaders:TrustedProxyHops"] = "1",
            [key] = value,
        });
    }

    [Fact]
    public async Task Development_trusts_hops_without_listed_proxies()
    {
        await using var app = await Host.StartAsync(new Dictionary<string, string?> { ["JeffOps:ForwardedHeaders:TrustedProxyHops"] = "1" }, environment: "Development");
    }

    [Fact]
    public void Trusted_hops_enable_for_and_proto_with_the_known_proxies()
    {
        var options = new ForwardedHeadersOptions();
        var trusted = new TrustedProxyOptions { TrustedProxyHops = 2 };
        trusted.KnownProxies.Add("10.0.0.5");
        trusted.KnownNetworks.Add("10.1.0.0/16");

        ForwardedHeadersExtensions.Apply(options, trusted);

        options.ForwardedHeaders.ShouldBe(Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto);
        options.ForwardLimit.ShouldBe(2);
        options.KnownProxies.ShouldBe([IPAddress.Parse("10.0.0.5")]);
        options.KnownIPNetworks.ShouldHaveSingleItem();
    }

    [Fact]
    public void No_hops_trusts_nothing()
    {
        var options = new ForwardedHeadersOptions();

        ForwardedHeadersExtensions.Apply(options, new TrustedProxyOptions());

        options.ForwardedHeaders.ShouldBe(Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.None);
        options.KnownProxies.ShouldBeEmpty();
    }
}

public sealed class AllowedHostsTests
{
    [Theory]
    [InlineData("*")]
    [InlineData("auth.example.com;*")]
    public async Task Outside_development_any_host_fails_startup(string allowedHosts) =>
        (await Should.ThrowAsync<OptionsValidationException>(() => Host.StartAsync(Host.NoProxy.With("AllowedHosts", allowedHosts))))
            .Message.ShouldContain("AllowedHosts");

    [Fact]
    public async Task Named_hosts_are_accepted()
    {
        await using var app = await Host.StartAsync(Host.NoProxy.With("AllowedHosts", "auth.example.com"));
    }

    [Fact]
    public async Task Development_accepts_any_host()
    {
        await using var app = await Host.StartAsync(Host.NoProxy.With("AllowedHosts", "*"), environment: "Development");
    }
}

public sealed class OriginLockTests
{
    private const string FrontDoorId = "1b2c3d4e-0000-4000-8000-000000000001";

    private static async Task<HttpStatusCode> GetAsync(WebApplication app, string path, string? header)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (header is not null)
        {
            request.Headers.Add("X-Azure-FDID", header);
        }

        return (await app.GetTestClient().SendAsync(request, TestContext.Current.CancellationToken)).StatusCode;
    }

    [Fact]
    public async Task Requests_without_the_edge_header_are_refused()
    {
        await using var app = await Host.StartAsync(Host.NoProxy.With("JeffOps:OriginLock:ExpectedValue", FrontDoorId));

        (await GetAsync(app, "/", null)).ShouldBe(HttpStatusCode.Forbidden);
        (await GetAsync(app, "/", "another-profile")).ShouldBe(HttpStatusCode.Forbidden);
        (await GetAsync(app, "/", FrontDoorId)).ShouldBe(HttpStatusCode.OK);
        (await GetAsync(app, "/health", null)).ShouldBe(HttpStatusCode.OK, "health probes are exempt");
    }

    [Fact]
    public async Task The_lock_is_off_without_an_expected_value()
    {
        await using var app = await Host.StartAsync(Host.NoProxy);

        (await GetAsync(app, "/", null)).ShouldBe(HttpStatusCode.OK);
    }
}

public sealed class DataProtectionTests
{
    private static string SelfSignedPfx()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=jeffops-kek-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return Convert.ToBase64String(certificate.Export(X509ContentType.Pfx));
    }

    private static async Task<(WebApplication App, MemoryXmlRepository Repository)> StartAsync(Dictionary<string, string?> settings, string environment = "Production")
    {
        var repository = new MemoryXmlRepository();
        var app = await Host.StartAsync(Host.NoProxy.Concat(settings).ToDictionary(), environment, builder =>
        {
            builder.Services.AddJeffOpsDataProtection(builder.Configuration);
            builder.Services.Configure<KeyManagementOptions>(options => options.XmlRepository = repository);
        });
        return (app, repository);
    }

    [Fact]
    public async Task Outside_development_a_missing_kek_fails_startup() =>
        await Should.ThrowAsync<OptionsValidationException>(() => StartAsync([]));

    [Fact]
    public async Task Development_runs_without_a_kek()
    {
        var (app, _) = await StartAsync([], environment: "Development");
        await app.DisposeAsync();
    }

    [Fact]
    public async Task With_a_kek_payloads_round_trip_and_stored_keys_are_encrypted()
    {
        var (app, repository) = await StartAsync(new()
        {
            ["JeffOps:DataProtection:KekCertificate"] = SelfSignedPfx(),
            ["JeffOps:DataProtection:ApplicationName"] = "jeffops-tests",
        });
        await using var _ = app;

        var protector = app.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector("test");
        protector.Unprotect(protector.Protect("secret payload")).ShouldBe("secret payload");

        var stored = repository.GetAllElements().ShouldHaveSingleItem().ToString();
        stored.ShouldContain("EncryptedData");
        stored.ShouldNotContain("<masterKey");
    }

    [Fact]
    public async Task A_key_directory_persists_the_key_ring_there_encrypted()
    {
        var directory = Directory.CreateTempSubdirectory("jeffops-keys-");
        try
        {
            var app = await Host.StartAsync(Host.NoProxy.Concat(new Dictionary<string, string?>
            {
                ["JeffOps:DataProtection:KekCertificate"] = SelfSignedPfx(),
                ["JeffOps:DataProtection:KeyDirectory"] = directory.FullName,
            }).ToDictionary(), "Production", builder => builder.Services.AddJeffOpsDataProtection(builder.Configuration));
            await using (app)
            {
                var protector = app.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector("test");
                protector.Unprotect(protector.Protect("secret payload")).ShouldBe("secret payload");
            }

            var stored = File.ReadAllText(directory.GetFiles("key-*.xml").ShouldHaveSingleItem().FullName);
            stored.ShouldContain("EncryptedData");
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void A_malformed_kek_fails_at_registration()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["JeffOps:DataProtection:KekCertificate"] = "not base64!",
        }).Build();

        Should.Throw<InvalidOperationException>(() => services.AddJeffOpsDataProtection(configuration))
            .Message.ShouldContain("KekCertificate");
    }

    private sealed class MemoryXmlRepository : IXmlRepository
    {
        private readonly List<XElement> _elements = [];

        public IReadOnlyCollection<XElement> GetAllElements()
        {
            lock (_elements)
            {
                return [.. _elements];
            }
        }

        public void StoreElement(XElement element, string friendlyName)
        {
            lock (_elements)
            {
                _elements.Add(element);
            }
        }
    }
}

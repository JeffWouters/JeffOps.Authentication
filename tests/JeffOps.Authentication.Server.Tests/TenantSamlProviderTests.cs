using System.Collections.Concurrent;
using System.Collections.Specialized;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Enterprise.Endpoints;
using JeffOps.Authentication.Enterprise.Infrastructure;
using JeffOps.Authentication.Federation;
using JeffOps.Authentication.Federation.Saml;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>SAML providers tenants register themselves (docs/DESIGN.md §8.4).</summary>
public sealed class TenantSamlProviderTests : IAsyncDisposable
{
    private const string TenantIdp = "https://idp.contoso.test/";
    private static readonly Guid Contoso = Guid.NewGuid();
    private static readonly Guid Fabrikam = Guid.NewGuid();

    private readonly string _database = TestDatabase.SqliteFile("tenant-providers");
    private readonly FakeDns _dns = new();
    private readonly ConcurrentDictionary<Guid, bool> _administrators = new();
    private readonly ConcurrentDictionary<Guid, bool> _operators = new();
    private readonly X509Certificate2 _idpCertificate = SelfSigned("CN=Contoso IdP");
    private TokenServerHost _host = null!;

    [Fact]
    public async Task A_tenant_signs_its_people_in_through_its_own_saml_provider()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await AllowAsync(Contoso);
        var provider = await RegisterAsync(admin);
        await PutAsync(admin, "enterprise/sso", new { provider, ssoOnly = false });

        using var browser = new Browser(_host);
        var signedIn = await SignInThroughAsync(browser, "account/login/discover?email=jo%40contoso.com&returnUrl=%2Fdone", provider, "jo@contoso.com", subject: "jo");

        signedIn.Headers.Location!.OriginalString.ShouldBe("/done");
        var account = await _host.FindAccountAsync("jo@contoso.com");
        account.ShouldNotBeNull().ExternalLogins.ShouldHaveSingleItem().Issuer.ShouldStartWith("urn:jeffops:tenant-provider:", customMessage: "logins are namespaced to the tenant's provider");
    }

    [Fact]
    public async Task A_tenant_provider_can_t_sign_in_addresses_outside_the_tenant_s_domains()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        var fabrikamAdmin = await AdministratorAsync("admin@fabrikam.com", Fabrikam);
        await VerifyDomainAsync(fabrikamAdmin, "fabrikam.com");
        await AllowAsync(Contoso);
        var provider = await RegisterAsync(admin);

        using var browser = new Browser(_host);
        var refused = await SignInThroughAsync(browser, $"signin/{provider}?returnUrl=%2Fdone", provider, "ceo@fabrikam.com", subject: "ceo");

        refused.Headers.Location!.OriginalString.ShouldContain("error=domain_not_allowed");
        (await _host.FindAccountAsync("ceo@fabrikam.com")).ShouldBeNull();
    }

    [Fact]
    public async Task Only_tenants_an_operator_allows_have_their_own_providers()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");

        var refused = await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.ProviderRoutes, admin, JsonContent.Create(ProviderData()));
        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await refused.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).ShouldContain("custom_providers_not_allowed");

        // A tenant administrator can't allow it themselves.
        (await _host.SendAsync(HttpMethod.Put, $"enterprise/admin/tenants/{Contoso}/custom-providers", admin, JsonContent.Create(new { allowed = true })))
            .StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        await AllowAsync(Contoso);
        var provider = await RegisterAsync(admin);
        (await _host.Client.GetAsync(new Uri($"signin/saml/{provider}/metadata", UriKind.Relative), TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);

        // Withdrawn: the provider stops working (within a minute, its settings' cache).
        await AllowAsync(Contoso, allowed: false);
        _host.Time.Advance(TimeSpan.FromMinutes(2));
        (await _host.Client.GetAsync(new Uri($"signin/saml/{provider}/metadata", UriKind.Relative), TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Provider_settings_must_be_complete_and_point_at_public_https_hosts()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await AllowAsync(Contoso);

        foreach (var bad in new object[]
        {
            new { displayName = "Corp", entityId = TenantIdp },                                               // no metadata, no SSO URL
            new { displayName = "Corp", entityId = TenantIdp, metadataUrl = "http://idp.contoso.test/md" },    // not HTTPS
            new { displayName = "Corp", entityId = TenantIdp, metadataUrl = "https://169.254.169.254/latest" }, // an address, not a host
            new { displayName = "Corp", entityId = TenantIdp, singleSignOnUrl = "https://idp.contoso.test/sso", signingCertificates = new[] { "not a certificate" } },
        })
        {
            (await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.ProviderRoutes, admin, JsonContent.Create(bad)))
                .StatusCode.ShouldBe(HttpStatusCode.BadRequest, JsonSerializer.Serialize(bad));
        }
    }

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("2001:4860:4860::8888", true)]
    [InlineData("127.0.0.1", false)]
    [InlineData("10.1.2.3", false)]
    [InlineData("172.20.0.1", false)]
    [InlineData("192.168.1.1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("100.64.0.1", false)]
    [InlineData("0.0.0.0", false)]
    [InlineData("::1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("::ffff:10.0.0.1", false)]
    public void Tenant_metadata_is_fetched_from_public_addresses_only(string address, bool allowed) =>
        PublicNetwork.IsPublic(IPAddress.Parse(address)).ShouldBe(allowed);

    public async ValueTask DisposeAsync()
    {
        _idpCertificate.Dispose();
        if (_host is not null)
        {
            await _host.DisposeAsync();
        }

        TestDatabase.DeleteSqlite(_database);
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private async Task StartAsync()
    {
        _host = await TokenServerHost.StartAsync(
            new() { ["JeffOps:TokenServer:Federation:OpenRegistration"] = "false" },
            configure: builder =>
            {
                builder.Services.AddSingleton(_dns);
                var authentication = new AuthenticationBuilder(builder.Services, builder.Configuration);
                authentication.AddEnterprise().UseDnsResolver<FakeDns.Scoped>().UseTestDatabase(_database);
                authentication.AddSamlTenantProviders();
                builder.Services.AddAuthorizationBuilder()
                    .AddPolicy("auth.enterprise.manage", policy => policy.RequireAssertion(context =>
                        Guid.TryParse(context.User.FindFirst("sub")?.Value, out var user) && _administrators.ContainsKey(user)))
                    .AddPolicy("auth.enterprise.operate", policy => policy.RequireAssertion(context =>
                        Guid.TryParse(context.User.FindFirst("sub")?.Value, out var user) && _operators.ContainsKey(user)));
            },
            cookieSignIn: true,
            map: app =>
            {
                app.MapJeffOpsEnterprise();
                app.MapJeffOpsSaml();
            });
        _host.Tenants.Tenants[Contoso] = new TenantInfo(Contoso, null, true);
        _host.Tenants.Tenants[Fabrikam] = new TenantInfo(Fabrikam, null, true);
    }

    private async Task<string> AdministratorAsync(string email, Guid tenant)
    {
        var account = await _host.CreateAccountAsync(email);
        _host.Tenants.Memberships.GetOrAdd(account.Id, _ => []).Add(new TenantMembership(tenant, null, null, AccessLevel.Tenant));
        _administrators[account.Id] = true;
        return (await _host.SignInAsync(account.Id)).AccessToken!;
    }

    private async Task AllowAsync(Guid tenant, bool allowed = true)
    {
        var account = await _host.CreateAccountAsync($"operator-{Guid.NewGuid():N}@platform.test");
        _operators[account.Id] = true;
        var token = (await _host.SignInAsync(account.Id)).AccessToken!;
        (await _host.SendAsync(HttpMethod.Put, $"enterprise/admin/tenants/{tenant}/custom-providers", token, JsonContent.Create(new { allowed })))
            .StatusCode.ShouldBe(HttpStatusCode.NoContent);
    }

    private object ProviderData() => new
    {
        displayName = "Contoso",
        entityId = TenantIdp,
        singleSignOnUrl = "https://idp.contoso.test/sso",
        signingCertificates = new[] { Convert.ToBase64String(_idpCertificate.RawData) },
    };

    private async Task<string> RegisterAsync(string admin)
    {
        var created = await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.ProviderRoutes, admin, JsonContent.Create(ProviderData()));
        created.StatusCode.ShouldBe(HttpStatusCode.OK, await created.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return (await created.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("name").GetString()!;
    }

    private async Task VerifyDomainAsync(string admin, string domain)
    {
        var claimed = await ReadOkAsync(await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.DomainRoutes, admin, JsonContent.Create(new { domain })));
        _dns.Records[claimed.GetProperty("recordName").GetString()!] = [claimed.GetProperty("recordValue").GetString()!];
        await ReadOkAsync(await _host.SendAsync(HttpMethod.Post, $"enterprise/domains/{claimed.GetProperty("id").GetString()}/verify", admin));
    }

    private async Task PutAsync(string token, string path, object body) =>
        await ReadOkAsync(await _host.SendAsync(HttpMethod.Put, path, token, JsonContent.Create(body)));

    private static async Task<JsonElement> ReadOkAsync(HttpResponseMessage response)
    {
        response.StatusCode.ShouldBe(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Follows <paramref name="startPath"/>'s redirects to the tenant's provider, and answers the AuthnRequest as the provider
    /// would, for <paramref name="email"/>.
    /// </summary>
    private async Task<HttpResponseMessage> SignInThroughAsync(Browser browser, string startPath, string provider, string email, string subject)
    {
        var location = new Uri(startPath, UriKind.Relative);
        while (!location.IsAbsoluteUri)
        {
            var step = await browser.GetAsync(null!, location.OriginalString);
            step.StatusCode.ShouldBe(HttpStatusCode.Redirect, await step.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            location = step.Headers.Location!;
        }

        location.GetLeftPart(UriPartial.Path).ShouldBe("https://idp.contoso.test/sso");

        var request = new Saml2AuthnRequest(new Saml2Configuration { Issuer = TenantIdp });
        new Saml2RedirectBinding().ReadSamlRequest(
            new ITfoxtec.Identity.Saml2.Http.HttpRequest { Method = "GET", Query = System.Web.HttpUtility.ParseQueryString(location.Query), QueryString = location.Query, Form = new NameValueCollection() },
            request);

        var response = new Saml2AuthnResponse(new Saml2Configuration { Issuer = TenantIdp, SigningCertificate = _idpCertificate })
        {
            InResponseTo = new Saml2Id(request.IdAsString),
            Status = Saml2StatusCodes.Success,
            Destination = request.AssertionConsumerServiceUrl,
            NameId = new Saml2NameIdentifier(subject, new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")),
            ClaimsIdentity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, subject),
                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", email),
            ]),
        };
        response.CreateSecurityToken(request.Issuer, AuthnContextClassTypes.PasswordProtectedTransport, null, 5, 60);
        var binding = new Saml2PostBinding();
        binding.Bind(response);

        return await browser.SendAsync(new HttpRequestMessage(HttpMethod.Post, $"signin/saml/{provider}/acs")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["SAMLResponse"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(binding.XmlDocument.OuterXml)) }),
        });
    }

    private static X509Certificate2 SelfSigned(string subject)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
    }
}

using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Enterprise.Endpoints;
using JeffOps.Authentication.Enterprise.Infrastructure;
using JeffOps.Authentication.Federation.Oidc;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>OpenID Connect providers tenants register themselves (docs/DESIGN.md §8.4).</summary>
public sealed class TenantOidcProviderTests : IAsyncDisposable
{
    private const string Issuer = "https://idp.contoso.test";
    private const string ClientId = "jeffops-at-contoso";
    private const string ClientSecret = "s3cret-from-contoso";
    private static readonly Guid Contoso = Guid.NewGuid();
    private static readonly Guid Fabrikam = Guid.NewGuid();

    private readonly string _database = TestDatabase.SqliteFile("tenant-oidc");
    private readonly FakeDns _dns = new();
    private readonly ConcurrentDictionary<Guid, bool> _administrators = new();
    private readonly ConcurrentDictionary<Guid, bool> _operators = new();
    private readonly FakeOidcProvider _idp = new(Issuer);
    private TokenServerHost _host = null!;

    [Fact]
    public async Task A_tenant_signs_its_people_in_through_its_own_oidc_provider()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await AllowAsync(Contoso);
        var created = await RegisterAsync(admin);
        created.GetProperty("hasClientSecret").GetBoolean().ShouldBeTrue();
        created.ToString().ShouldNotContain(ClientSecret, customMessage: "the secret is never shown again");
        var provider = created.GetProperty("name").GetString()!;
        await ReadOkAsync(await _host.SendAsync(HttpMethod.Put, "enterprise/sso", admin, JsonContent.Create(new { provider, ssoOnly = false })));

        using var browser = new Browser(_host);
        var signedIn = await SignInThroughAsync(browser, "account/login/discover?email=jo%40contoso.com&returnUrl=%2Fdone", "jo@contoso.com");

        signedIn.Headers.Location!.OriginalString.ShouldBe("/done");
        _idp.LastClientAuthentication.ShouldBe($"{ClientId}:{ClientSecret}", "the client secret is sent with HTTP Basic");
        var account = await _host.FindAccountAsync("jo@contoso.com");
        account.ShouldNotBeNull().ExternalLogins.ShouldHaveSingleItem().Issuer.ShouldStartWith("urn:jeffops:tenant-provider:", customMessage: "logins are namespaced to the tenant's provider");

        await using var scope = _host.Services.CreateAsyncScope();
        var stored = await scope.ServiceProvider.GetRequiredService<EnterpriseDbContext>().OidcProviders.SingleAsync(TestContext.Current.CancellationToken);
        stored.ProtectedClientSecret.ShouldNotBeNull().ShouldNotContain(ClientSecret, customMessage: "the secret is stored encrypted");
    }

    [Fact]
    public async Task A_fresh_sign_in_is_asked_of_the_tenant_s_provider_and_an_older_authentication_is_refused()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await AllowAsync(Contoso);
        var provider = (await RegisterAsync(admin)).GetProperty("name").GetString()!;
        await ReadOkAsync(await _host.SendAsync(HttpMethod.Put, "enterprise/sso", admin, JsonContent.Create(new { provider, ssoOnly = false })));
        var returnUrl = $"/done?jeffops_signed_in_after={_host.Time.GetUtcNow().ToUnixTimeSeconds()}";
        var start = $"account/login/discover?email=jo%40contoso.com&returnUrl={Uri.EscapeDataString(returnUrl)}";

        using (var browser = new Browser(_host))
        {
            _idp.AuthTime = _host.Time.GetUtcNow().AddHours(-1);
            (await SignInThroughAsync(browser, start, "jo@contoso.com")).Headers.Location!.OriginalString.ShouldContain("error=reauthentication_required");
            _idp.LastAuthorization!["prompt"].ShouldBe("login");
            _idp.LastAuthorization["max_age"].ShouldNotBeNull();
        }

        using (var browser = new Browser(_host))
        {
            _idp.AuthTime = _host.Time.GetUtcNow();
            (await SignInThroughAsync(browser, start, "jo@contoso.com")).Headers.Location!.OriginalString.ShouldBe(returnUrl);
        }
    }

    [Fact]
    public async Task A_tenant_oidc_provider_can_t_sign_in_addresses_outside_the_tenant_s_domains()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        var fabrikamAdmin = await AdministratorAsync("admin@fabrikam.com", Fabrikam);
        await VerifyDomainAsync(fabrikamAdmin, "fabrikam.com");
        await AllowAsync(Contoso);
        var provider = (await RegisterAsync(admin)).GetProperty("name").GetString()!;

        using var browser = new Browser(_host);
        var refused = await SignInThroughAsync(browser, $"signin/{provider}?returnUrl=%2Fdone", "ceo@fabrikam.com");

        refused.Headers.Location!.OriginalString.ShouldContain("error=domain_not_allowed");
        (await _host.FindAccountAsync("ceo@fabrikam.com")).ShouldBeNull();
    }

    [Fact]
    public async Task Forged_or_misdirected_answers_sign_nobody_in()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await AllowAsync(Contoso);
        var provider = (await RegisterAsync(admin)).GetProperty("name").GetString()!;

        // Signed with a key the provider never published.
        using (var browser = new Browser(_host))
        {
            _idp.Forge = token => token with { SigningKey = FakeOidcProvider.NewKey("impostor") };
            (await SignInThroughAsync(browser, $"signin/{provider}?returnUrl=%2Fdone", "jo@contoso.com")).Headers.Location!.OriginalString.ShouldContain("error=provider_error");
        }

        // Issued for this browser's sign-in, but with another nonce.
        using (var browser = new Browser(_host))
        {
            _idp.Forge = token => token with { Nonce = "not-the-nonce" };
            (await SignInThroughAsync(browser, $"signin/{provider}?returnUrl=%2Fdone", "jo@contoso.com")).Headers.Location!.OriginalString.ShouldContain("error=provider_error");
        }

        // Issued to another client.
        using (var browser = new Browser(_host))
        {
            _idp.Forge = token => token with { Audience = "someone-else" };
            (await SignInThroughAsync(browser, $"signin/{provider}?returnUrl=%2Fdone", "jo@contoso.com")).Headers.Location!.OriginalString.ShouldContain("error=provider_error");
        }

        // A victim's code and state, carried to another browser: no sign-in is pending there.
        _idp.Forge = null;
        using var victim = new Browser(_host);
        using var attacker = new Browser(_host);
        var callback = await AuthorizeAtProviderAsync(victim, $"signin/{provider}?returnUrl=%2Fdone", "jo@contoso.com");
        (await attacker.GetAsync(null!, callback)).Headers.Location!.OriginalString.ShouldContain("error=signin_expired");

        (await _host.FindAccountAsync("jo@contoso.com")).ShouldBeNull();
    }

    [Fact]
    public async Task A_discovery_document_for_another_issuer_is_refused()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await AllowAsync(Contoso);
        var provider = (await RegisterAsync(admin)).GetProperty("name").GetString()!;
        _idp.AnnouncedIssuer = "https://evil.test";

        using var browser = new Browser(_host);
        var start = await browser.GetAsync(null!, $"signin/oidc/{provider}?returnUrl=%2Fdone");

        start.Headers.Location!.OriginalString.ShouldContain("error=provider_unavailable");
    }

    [Fact]
    public async Task Only_allowed_tenants_register_oidc_providers_and_settings_must_be_safe()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");

        var refused = await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.OidcProviderRoutes, admin, JsonContent.Create(ProviderData()));
        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await refused.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).ShouldContain("custom_providers_not_allowed");

        await AllowAsync(Contoso);
        foreach (var bad in new object[]
        {
            new { displayName = "Corp", issuer = "http://idp.contoso.test", clientId = ClientId },          // not HTTPS
            new { displayName = "Corp", issuer = "https://10.0.0.5", clientId = ClientId },                  // an address, not a host
            new { displayName = "Corp", issuer = Issuer },                                                    // no client id
            new { displayName = "Corp", issuer = Issuer, clientId = ClientId, scopes = new[] { "a b" } },     // not a scope
        })
        {
            (await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.OidcProviderRoutes, admin, JsonContent.Create(bad)))
                .StatusCode.ShouldBe(HttpStatusCode.BadRequest, JsonSerializer.Serialize(bad));
        }

        var provider = (await RegisterAsync(admin)).GetProperty("name").GetString()!;
        (await _host.Client.GetAsync(new Uri($"signin/oidc/{provider}", UriKind.Relative), TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Redirect);

        await AllowAsync(Contoso, allowed: false);
        (await _host.Client.GetAsync(new Uri($"signin/oidc/{provider}", UriKind.Relative), TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Signing_out_here_signs_out_at_the_provider_too()
    {
        var provider = await StartWithProviderAsync();
        using var browser = new Browser(_host);
        await SignInThroughAsync(browser, "account/login/discover?email=jo%40contoso.com&returnUrl=%2Fdone", "jo@contoso.com");

        var signOut = await browser.NavigateAsync("connect/endsession");
        signOut.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        var toProvider = signOut.Headers.Location!;
        toProvider.GetLeftPart(UriPartial.Path).ShouldBe($"{Issuer}/logout");
        var query = System.Web.HttpUtility.ParseQueryString(toProvider.Query);
        query["id_token_hint"].ShouldBe(_idp.LastIdToken);
        query["client_id"].ShouldBe(ClientId);
        query["post_logout_redirect_uri"].ShouldBe($"https://localhost/signin/oidc/{provider}/signed-out");

        // The provider logs the user out and sends the browser back; signing out here then completes.
        var back = await browser.GetAsync(null!, $"signin/oidc/{provider}/signed-out?state={Uri.EscapeDataString(query["state"]!)}");
        back.Headers.Location!.OriginalString.ShouldStartWith("/connect/endsession");
        var finished = await browser.GetAsync(null!, back.Headers.Location.OriginalString.TrimStart('/'));
        finished.Headers.Location!.OriginalString.ShouldNotContain("idp.contoso.test", customMessage: "signed out here already, the second pass completes");

        (await browser.GetAsync(null!, $"signin/oidc/{provider}/signed-out?state=forged")).Headers.Location!.OriginalString.ShouldBe("/");
    }

    [Fact]
    public async Task The_provider_s_back_channel_logout_ends_the_session_it_names()
    {
        var provider = await StartWithProviderAsync();
        using var laptop = new Browser(_host);
        await SignInThroughAsync(laptop, $"signin/{provider}?returnUrl=%2Fdone", "jo@contoso.com");
        var laptopSession = _idp.LastSid!;
        var laptopTokens = await AuthorizeAsync(laptop);
        using var phone = new Browser(_host);
        await SignInThroughAsync(phone, $"signin/{provider}?returnUrl=%2Fdone", "jo@contoso.com");
        var phoneTokens = await AuthorizeAsync(phone);

        (await LogoutAsync(provider, _idp.LogoutToken(sid: laptopSession))).StatusCode.ShouldBe(HttpStatusCode.OK);

        (await _host.RefreshAsync(laptopTokens.RefreshToken!)).Error.ShouldBe("invalid_grant");
        (await _host.RefreshAsync(phoneTokens.RefreshToken!)).AccessToken.ShouldNotBeNull("the phone's session is another provider session");

        // The laptop's browser must sign in again; the phone's still gets codes.
        (await laptop.GetAsync(null!, AuthorizePath())).Headers.Location!.OriginalString.ShouldContain("account/login");
        TokenServerHost.QueryValue((await phone.GetAsync(null!, AuthorizePath())).Headers.Location!, "code").ShouldNotBeNull();
    }

    [Fact]
    public async Task A_back_channel_logout_naming_only_the_user_ends_all_their_sessions_from_the_provider()
    {
        var provider = await StartWithProviderAsync();
        using var laptop = new Browser(_host);
        await SignInThroughAsync(laptop, $"signin/{provider}?returnUrl=%2Fdone", "jo@contoso.com");
        var laptopTokens = await AuthorizeAsync(laptop);
        using var phone = new Browser(_host);
        await SignInThroughAsync(phone, $"signin/{provider}?returnUrl=%2Fdone", "jo@contoso.com");
        var phoneTokens = await AuthorizeAsync(phone);

        (await LogoutAsync(provider, _idp.LogoutToken(sub: "subject-jo@contoso.com"))).StatusCode.ShouldBe(HttpStatusCode.OK);

        (await _host.RefreshAsync(laptopTokens.RefreshToken!)).Error.ShouldBe("invalid_grant");
        (await _host.RefreshAsync(phoneTokens.RefreshToken!)).Error.ShouldBe("invalid_grant");
    }

    [Fact]
    public async Task Invalid_logout_tokens_are_refused_and_end_nothing()
    {
        var provider = await StartWithProviderAsync();
        using var browser = new Browser(_host);
        await SignInThroughAsync(browser, $"signin/{provider}?returnUrl=%2Fdone", "jo@contoso.com");
        var sid = _idp.LastSid!;
        var tokens = await AuthorizeAsync(browser);

        var impostor = FakeOidcProvider.NewKey("impostor");
        foreach (var forged in new[]
        {
            _idp.LogoutToken(sid: sid, key: impostor),                                   // not the provider's key
            _idp.LogoutToken(sid: sid, audience: "someone-else"),                        // another client
            _idp.LogoutToken(sid: sid, extra: new() { ["nonce"] = "n" }),               // an ID token posing as one
            _idp.LogoutToken(sid: sid, logoutEvent: false),                              // not the logout event
            _idp.LogoutToken(sid: sid, issuedAt: DateTime.UtcNow.AddHours(-1)),          // old
            _idp.LogoutToken(),                                                          // names nobody
        })
        {
            (await LogoutAsync(provider, forged)).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        }

        (await _host.RefreshAsync(tokens.RefreshToken!)).AccessToken.ShouldNotBeNull("nothing was ended");

        var valid = _idp.LogoutToken(sid: sid);
        (await LogoutAsync(provider, valid)).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await LogoutAsync(provider, valid)).StatusCode.ShouldBe(HttpStatusCode.BadRequest, "a logout token works once");
    }

    public async ValueTask DisposeAsync()
    {
        _idp.Dispose();
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
                authentication.AddOidcTenantProviders();
                builder.Services.AddHttpClient(TenantOidcEndpoints.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => _idp);
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
                app.MapJeffOpsTenantOidc();
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

    /// <summary>A started host with Contoso's verified domain, allowed custom providers, and its OIDC provider as SSO provider.</summary>
    private async Task<string> StartWithProviderAsync()
    {
        await StartAsync();
        var admin = await AdministratorAsync("admin@contoso.com", Contoso);
        await VerifyDomainAsync(admin, "contoso.com");
        await AllowAsync(Contoso);
        var provider = (await RegisterAsync(admin)).GetProperty("name").GetString()!;
        await ReadOkAsync(await _host.SendAsync(HttpMethod.Put, "enterprise/sso", admin, JsonContent.Create(new { provider, ssoOnly = false })));
        return provider;
    }

    private async Task<HttpResponseMessage> LogoutAsync(string provider, string logoutToken) =>
        await _host.Client.PostAsync(
            new Uri($"signin/oidc/{provider}/backchannel-logout", UriKind.Relative),
            new FormUrlEncodedContent(new Dictionary<string, string> { ["logout_token"] = logoutToken }),
            TestContext.Current.CancellationToken);

    private string _verifier = string.Empty;

    private string AuthorizePath()
    {
        _verifier = SoftwareAuthenticator.Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = SoftwareAuthenticator.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(_verifier)));
        return $"connect/authorize?client_id={TokenServerHost.BffClient}&response_type=code&redirect_uri={Uri.EscapeDataString(TokenServerHost.BffRedirect)}" +
            $"&scope={Uri.EscapeDataString("openid offline_access api")}&code_challenge={challenge}&code_challenge_method=S256&state=xyz";
    }

    /// <summary>The BFF's authorization code flow in <paramref name="browser"/>'s session.</summary>
    private async Task<TokenResponse> AuthorizeAsync(Browser browser)
    {
        var authorize = await browser.GetAsync(null!, AuthorizePath());
        var code = TokenServerHost.QueryValue(authorize.Headers.Location!, "code").ShouldNotBeNull(authorize.Headers.Location!.ToString());
        var tokens = await _host.TokenAsync(new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TokenServerHost.BffRedirect,
            ["code_verifier"] = _verifier,
            ["client_id"] = TokenServerHost.BffClient,
            ["client_secret"] = TokenServerHost.BffSecret,
        });
        tokens.RefreshToken.ShouldNotBeNull();
        return tokens;
    }

    private static object ProviderData() => new
    {
        displayName = "Contoso",
        issuer = Issuer,
        clientId = ClientId,
        clientSecret = ClientSecret,
        multiFactorAcrValues = new[] { "urn:contoso:mfa" },
    };

    private async Task<JsonElement> RegisterAsync(string admin) =>
        await ReadOkAsync(await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.OidcProviderRoutes, admin, JsonContent.Create(ProviderData())));

    private async Task VerifyDomainAsync(string admin, string domain)
    {
        var claimed = await ReadOkAsync(await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.DomainRoutes, admin, JsonContent.Create(new { domain })));
        _dns.Records[claimed.GetProperty("recordName").GetString()!] = [claimed.GetProperty("recordValue").GetString()!];
        await ReadOkAsync(await _host.SendAsync(HttpMethod.Post, $"enterprise/domains/{claimed.GetProperty("id").GetString()}/verify", admin));
    }

    private static async Task<JsonElement> ReadOkAsync(HttpResponseMessage response)
    {
        response.StatusCode.ShouldBe(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
    }

    /// <summary>Follows <paramref name="startPath"/> to the provider, signs <paramref name="email"/> in there, and returns the callback (local) URL.</summary>
    private async Task<string> AuthorizeAtProviderAsync(Browser browser, string startPath, string email)
    {
        var location = new Uri(startPath, UriKind.Relative);
        while (!location.IsAbsoluteUri)
        {
            var step = await browser.GetAsync(null!, location.OriginalString);
            step.StatusCode.ShouldBe(HttpStatusCode.Redirect, await step.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            location = step.Headers.Location!;
        }

        location.GetLeftPart(UriPartial.Path).ShouldBe($"{Issuer}/authorize");
        var callback = _idp.Authorize(System.Web.HttpUtility.ParseQueryString(location.Query), email);
        callback.GetLeftPart(UriPartial.Authority).ShouldBe("https://localhost");
        return callback.PathAndQuery;
    }

    private async Task<HttpResponseMessage> SignInThroughAsync(Browser browser, string startPath, string email) =>
        await browser.GetAsync(null!, await AuthorizeAtProviderAsync(browser, startPath, email));
}

/// <summary>
/// A minimal OpenID Connect provider: discovery, keys, and a token endpoint that checks PKCE and client authentication.
/// <see cref="Authorize"/> stands in for the user signing in at the provider.
/// </summary>
internal sealed class FakeOidcProvider(string issuer) : HttpMessageHandler
{
    private readonly string _issuer = issuer;
    private readonly ConcurrentDictionary<string, IdToken> _codes = new(StringComparer.Ordinal);
    private readonly RsaSecurityKey _key = NewKey("k1");

    public string? AnnouncedIssuer { get; set; }

    public Func<IdToken, IdToken>? Forge { get; set; }

    public string? LastClientAuthentication { get; private set; }

    /// <summary>The provider session (<c>sid</c>) of the last sign-in.</summary>
    public string? LastSid { get; private set; }

    /// <summary>The last ID token issued.</summary>
    public string? LastIdToken { get; private set; }

    /// <summary>The last authorization request's parameters.</summary>
    public System.Collections.Specialized.NameValueCollection? LastAuthorization { get; private set; }

    /// <summary>When the provider says it authenticated the user (<c>auth_time</c>); not said when null.</summary>
    public DateTimeOffset? AuthTime { get; set; }

    public static RsaSecurityKey NewKey(string keyId) => new(RSA.Create(2048)) { KeyId = keyId };

    /// <summary>The user signs in at the provider; returns where the provider sends the browser back to.</summary>
    public Uri Authorize(System.Collections.Specialized.NameValueCollection query, string email)
    {
        query["response_type"].ShouldBe("code");
        query["code_challenge_method"].ShouldBe("S256");
        var code = Guid.NewGuid().ToString("N");
        LastAuthorization = query;
        var token = new IdToken(query["client_id"]!, query["nonce"]!, query["code_challenge"]!, query["redirect_uri"]!, "subject-" + email, email, _key)
        {
            Sid = "idp-session-" + Guid.NewGuid().ToString("N"),
            AuthTime = AuthTime,
        };
        _codes[code] = Forge?.Invoke(token) ?? token;
        LastSid = token.Sid;
        return new Uri($"{query["redirect_uri"]}?code={code}&state={Uri.EscapeDataString(query["state"]!)}");
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.GetLeftPart(UriPartial.Path);
        if (path == $"{_issuer}/.well-known/openid-configuration")
        {
            return Json(new Dictionary<string, object>
            {
                ["issuer"] = AnnouncedIssuer ?? _issuer,
                ["authorization_endpoint"] = $"{_issuer}/authorize",
                ["token_endpoint"] = $"{_issuer}/token",
                ["jwks_uri"] = $"{_issuer}/jwks",
                ["end_session_endpoint"] = $"{_issuer}/logout",
                ["token_endpoint_auth_methods_supported"] = new[] { "client_secret_basic" },
            });
        }

        if (path == $"{_issuer}/jwks")
        {
            var parameters = _key.Rsa.ExportParameters(false);
            return Json(new { keys = new[] { new { kty = "RSA", use = "sig", kid = _key.KeyId, alg = "RS256", n = Base64UrlEncoder.Encode(parameters.Modulus), e = Base64UrlEncoder.Encode(parameters.Exponent) } } });
        }

        if (path == $"{_issuer}/token" && request.Method == HttpMethod.Post)
        {
            LastClientAuthentication = request.Headers.Authorization is { Scheme: "Basic" } basic
                ? string.Join(':', Encoding.UTF8.GetString(Convert.FromBase64String(basic.Parameter!)).Split(':').Select(Uri.UnescapeDataString))
                : null;
            var form = System.Web.HttpUtility.ParseQueryString(await request.Content!.ReadAsStringAsync(cancellationToken));
            if (!_codes.TryRemove(form["code"] ?? string.Empty, out var token)
                || form["redirect_uri"] != token.RedirectUri
                || Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(form["code_verifier"] ?? string.Empty))) != token.CodeChallenge)
            {
                return new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = JsonContent.Create(new { error = "invalid_grant" }) };
            }

            LastIdToken = token.Issue(_issuer);
            return Json(new { access_token = "at", token_type = "Bearer", id_token = LastIdToken });
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    /// <summary>A Back-Channel Logout 1.0 logout token, signed with the provider's key unless another is given.</summary>
    public string LogoutToken(
        string? sub = null, string? sid = null, RsaSecurityKey? key = null, string audience = "jeffops-at-contoso",
        Dictionary<string, object>? extra = null, bool logoutEvent = true, DateTime? issuedAt = null)
    {
        var claims = new Dictionary<string, object>
        {
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["events"] = new Dictionary<string, object> { [logoutEvent ? "http://schemas.openid.net/event/backchannel-logout" : "urn:other:event"] = new Dictionary<string, object>() },
        };
        if (sub is not null)
        {
            claims["sub"] = sub;
        }

        if (sid is not null)
        {
            claims["sid"] = sid;
        }

        foreach (var (name, value) in extra ?? [])
        {
            claims[name] = value;
        }

        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = audience,
            IssuedAt = issuedAt ?? DateTime.UtcNow,
            TokenType = "logout+jwt",
            Claims = claims,
            SigningCredentials = new SigningCredentials(key ?? _key, SecurityAlgorithms.RsaSha256),
        });
    }

    private static HttpResponseMessage Json(object body) => new(HttpStatusCode.OK) { Content = JsonContent.Create(body) };

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _key.Rsa.Dispose();
        }

        base.Dispose(disposing);
    }

    /// <summary>What the provider puts in the ID token for one sign-in (a test may forge parts of it).</summary>
    internal sealed record IdToken(string Audience, string Nonce, string CodeChallenge, string RedirectUri, string Subject, string Email, RsaSecurityKey SigningKey)
    {
        public string? Sid { get; init; }

        public DateTimeOffset? AuthTime { get; init; }

        public string Issue(string issuer)
        {
            var claims = new Dictionary<string, object> { ["sub"] = Subject, ["email"] = Email, ["nonce"] = Nonce, ["name"] = "Jo" };
            if (Sid is not null)
            {
                claims["sid"] = Sid;
            }

            if (AuthTime is { } authTime)
            {
                claims["auth_time"] = authTime.ToUnixTimeSeconds();
            }

            return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = Audience,
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow.AddMinutes(5),
                Claims = claims,
                SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.RsaSha256),
            });
        }
    }
}

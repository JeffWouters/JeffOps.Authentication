using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Bff;
using JeffOps.Authentication.Bff.Yarp;
using JeffOps.Authentication.Client.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>
/// The BFF end to end: token server, BFF with YARP, and an API validating platform tokens — the browser holds only the
/// session cookie (docs/DESIGN.md §9.1).
/// </summary>
public sealed partial class BffTests
{
    private const string BffSecret = "spa-bff-secret-that-is-at-least-thirty-two-chars";

    private sealed class Stack : IAsyncDisposable
    {
        public required TokenServerHost TokenServer { get; init; }

        public required WebApplication Bff { get; init; }

        public required WebApplication Api { get; init; }

        public required HttpClient Browser { get; init; }

        public required RoutingHandler Routes { get; init; }

        public async ValueTask DisposeAsync()
        {
            Browser.Dispose();
            await Bff.DisposeAsync();
            await Api.DisposeAsync();
            await TokenServer.DisposeAsync();
        }
    }

    private static async Task<Stack> StartAsync(string accessTokenLifetime = "00:15:00", DelegationSetup? delegation = null, bool tokenMediating = false, bool accountApi = false)
    {
        var routes = new RoutingHandler();
        var tokenServerSettings = new Dictionary<string, string?>
            {
                ["JeffOps:TokenServer:AccessTokenLifetime"] = accessTokenLifetime,
                ["JeffOps:TokenServer:Clients:3:ClientId"] = "spa-bff",
                ["JeffOps:TokenServer:Clients:3:ClientSecret"] = BffSecret,
                ["JeffOps:TokenServer:Clients:3:GrantTypes:0"] = "authorization_code",
                ["JeffOps:TokenServer:Clients:3:GrantTypes:1"] = "refresh_token",
                ["JeffOps:TokenServer:Clients:3:RedirectUris:0"] = "https://bff.test/bff/callback",
                ["JeffOps:TokenServer:Clients:3:BackchannelLogoutUri"] = "https://bff.test/bff/backchannel-logout",
                ["JeffOps:TokenServer:Clients:3:Scopes:0"] = "openid",
                ["JeffOps:TokenServer:Clients:3:Scopes:1"] = "profile",
                ["JeffOps:TokenServer:Clients:3:Scopes:2"] = "email",
                ["JeffOps:TokenServer:Clients:3:Scopes:3"] = "offline_access",
                ["JeffOps:TokenServer:Clients:3:Scopes:4"] = "api",
                ["JeffOps:TokenServer:Clients:3:Scopes:5"] = "account",
            };
        if (delegation is not null)
        {
            tokenServerSettings["JeffOps:TokenServer:Clients:3:GrantTypes:2"] = "urn:jeffops:grant-type:impersonation";
            tokenServerSettings["JeffOps:TokenServer:Clients:3:GrantTypes:3"] = "urn:jeffops:grant-type:tenant-switch";
        }

        var tokenServer = await TokenServerHost.StartAsync(
            tokenServerSettings,
            configure: builder =>
            {
                builder.Services.AddHttpClient("JeffOps.BackchannelLogout").ConfigurePrimaryHttpMessageHandler(() => routes.Clone());
                delegation?.ConfigureTokenServer(builder);
            },
            map: delegation is null ? null : DelegationSetup.MapTokenServer);
        routes.Add("localhost", tokenServer.CreateHandler());

        // The API: validates platform tokens like any resource service.
        var apiBuilder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        apiBuilder.WebHost.UseTestServer();
        apiBuilder.Logging.ClearProviders();
        apiBuilder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["JeffOps:Authentication:Authority"] = "https://localhost/",
            ["JeffOps:Authentication:Audiences:0"] = "api",
        });
        apiBuilder.Services.AddJeffOpsAuthenticationClient(apiBuilder.Configuration);
        apiBuilder.Services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, options => options.BackchannelHttpHandler = routes.Clone());
        var api = apiBuilder.Build();
        api.UseAuthentication();
        api.UseAuthorization();
        api.MapGet("/api/whoami", (ICurrentUser user, HttpRequest request) => new { user = user.UserId, cookie = request.Headers.Cookie.ToString() });
        api.MapPost("/api/things", () => "created");
        await api.StartAsync(TestContext.Current.CancellationToken);
        routes.Add("api.test", api.GetTestServer().CreateHandler());

        // The BFF: confidential client of the token server, proxying /api to the API.
        var bffBuilder = WebApplication.CreateSlimBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        bffBuilder.WebHost.UseTestServer();
        bffBuilder.Logging.ClearProviders();
        bffBuilder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["JeffOps:Bff:Authority"] = "https://localhost/",
            ["JeffOps:Bff:ClientId"] = "spa-bff",
            ["JeffOps:Bff:ClientSecret"] = BffSecret,
            ["JeffOps:Bff:Scopes:0"] = "profile",
            ["JeffOps:Bff:Scopes:1"] = "email",
            ["JeffOps:Bff:Scopes:2"] = "api",
            ["JeffOps:Bff:Delegation:Enabled"] = delegation is null ? "false" : "true",
            ["JeffOps:Bff:TokenMediating"] = tokenMediating ? "true" : "false",
            ["JeffOps:Bff:AccountApi"] = accountApi ? "true" : "false",
        });
        if (delegation is not null)
        {
            bffBuilder.Services.AddSingleton<TimeProvider>(tokenServer.Time);
        }

        bffBuilder.Services.AddJeffOpsBff(bffBuilder.Configuration);
        bffBuilder.Services.PostConfigureAll<HttpClientFactoryOptions>(options =>
            options.HttpMessageHandlerBuilderActions.Add(handler => handler.PrimaryHandler = routes.Clone()));
        bffBuilder.Services.AddReverseProxy()
            .LoadFromMemory(
                [
                    new RouteConfig { RouteId = "api", ClusterId = "api", Match = new RouteMatch { Path = "/api/{**rest}" } },
                ],
                [
                    new ClusterConfig { ClusterId = "api", Destinations = new Dictionary<string, DestinationConfig> { ["api"] = new() { Address = "https://api.test/" } } },
                ])
            .AddBffTransforms();
        bffBuilder.Services.AddSingleton<IForwarderHttpClientFactory>(new TestForwarderFactory(routes));
        var bff = bffBuilder.Build();
        bff.UseJeffOpsBff();
        bff.MapJeffOpsBff();
        bff.MapReverseProxy();
        await bff.StartAsync(TestContext.Current.CancellationToken);
        routes.Add("bff.test", bff.GetTestServer().CreateHandler());

        var browser = new HttpClient(new CookieJar { InnerHandler = routes.Clone() }) { BaseAddress = new Uri("https://bff.test/") };
        return new Stack { TokenServer = tokenServer, Bff = bff, Api = api, Browser = browser, Routes = routes };
    }

    private static async Task<Guid> SignInAsync(Stack stack, string? accountEmail = null, Action<Guid>? prepare = null)
    {
        var account = await stack.TokenServer.CreateAccountAsync(accountEmail ?? "ada@example.com");
        prepare?.Invoke(account.Id);

        var login = await stack.Browser.GetAsync(new Uri("bff/login?returnUrl=/app", UriKind.Relative), TestContext.Current.CancellationToken);
        login.StatusCode.ShouldBe(HttpStatusCode.Redirect, await login.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        login.Headers.Location!.Host.ShouldBe("localhost");

        using var authorize = new HttpRequestMessage(HttpMethod.Get, login.Headers.Location);
        authorize.Headers.Add(HeaderSignIn.Header, $"{account.Id}|pwd,mfa|{stack.TokenServer.Time.GetUtcNow().ToUnixTimeSeconds()}");
        var code = await stack.Browser.SendAsync(authorize, TestContext.Current.CancellationToken);
        code.Headers.Location!.ToString().ShouldStartWith("https://bff.test/bff/callback");

        var callback = await stack.Browser.GetAsync(code.Headers.Location, TestContext.Current.CancellationToken);
        callback.StatusCode.ShouldBe(HttpStatusCode.Redirect, await callback.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        callback.Headers.Location!.OriginalString.ShouldBe("/app");
        return account.Id;
    }

    [Fact]
    public async Task The_browser_signs_in_and_calls_the_api_with_only_a_session_cookie()
    {
        await using var stack = await StartAsync();
        var accountId = await SignInAsync(stack);

        var me = await stack.Browser.GetFromJsonAsync<JsonElement>(new Uri("bff/me", UriKind.Relative), TestContext.Current.CancellationToken);
        me.GetProperty("sub").GetString().ShouldBe(accountId.ToString());

        var whoami = await stack.Browser.GetFromJsonAsync<JsonElement>(new Uri("api/whoami", UriKind.Relative), TestContext.Current.CancellationToken);
        whoami.GetProperty("user").GetString().ShouldBe(accountId.ToString());
        whoami.GetProperty("cookie").GetString().ShouldBeEmpty("the session cookie never reaches the backend");
    }

    [Fact]
    public async Task The_token_server_s_own_apis_are_reached_through_the_bff_with_an_account_token_only()
    {
        await using var stack = await StartAsync(accountApi: true);
        await SignInAsync(stack);

        // The session's API token is meant for APIs; the account API needs the account token the BFF fetches for it.
        var pats = await stack.Browser.GetAsync(new Uri("bff/account/account/pats", UriKind.Relative), TestContext.Current.CancellationToken);
        pats.StatusCode.ShouldBe(HttpStatusCode.OK, await pats.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        (await stack.Browser.GetFromJsonAsync<JsonElement>(new Uri("api/whoami", UriKind.Relative), TestContext.Current.CancellationToken))
            .GetProperty("user").GetString().ShouldNotBeNull("the API still gets its own token after the narrowing refresh");

        // Only the token server's own API paths, and nothing that leaves them.
        foreach (var path in new[] { "bff/account/connect/token", "bff/account/account/..%2F..%2Fconnect%2Ftoken", "bff/account/.well-known/openid-configuration" })
        {
            (await stack.Browser.GetAsync(new Uri(path, UriKind.Relative), TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.NotFound, path);
        }

        using var post = new HttpRequestMessage(HttpMethod.Post, "bff/account/account/sessions/revoke");
        (await stack.Browser.SendAsync(post, TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Forbidden, "the CSRF header applies");
    }

    [Fact]
    public async Task Token_mediating_mode_hands_the_app_the_session_s_access_token_only_when_on()
    {
        await using (var proxyOnly = await StartAsync())
        {
            await SignInAsync(proxyOnly);
            (await TokenAsync(proxyOnly.Browser, csrf: true)).StatusCode.ShouldBe(HttpStatusCode.NotFound, "off by default");
        }

        await using var stack = await StartAsync(tokenMediating: true);
        var accountId = await SignInAsync(stack);

        (await TokenAsync(stack.Browser, csrf: false)).StatusCode.ShouldBe(HttpStatusCode.Forbidden, "the CSRF header is required");

        var response = await TokenAsync(stack.Browser, csrf: true);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        response.Headers.CacheControl!.NoStore.ShouldBeTrue();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        body.TryGetProperty("refresh_token", out _).ShouldBeFalse("the refresh token stays in the BFF");
        new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(body.GetProperty("access_token").GetString()).Subject.ShouldBe(accountId.ToString());
        body.GetProperty("expires_at").GetInt64().ShouldBeGreaterThan(DateTimeOffset.UtcNow.ToUnixTimeSeconds());

        // Without a session there is no token.
        using var anonymous = new HttpClient(stack.Routes.Clone()) { BaseAddress = new Uri("https://bff.test/") };
        (await TokenAsync(anonymous, csrf: true)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    private static async Task<HttpResponseMessage> TokenAsync(HttpClient browser, bool csrf)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "bff/token");
        if (csrf)
        {
            request.Headers.Add("X-JeffOps-Csrf", "1");
        }

        return await browser.SendAsync(request, TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task The_session_cookie_is_host_prefixed_http_only_and_lax()
    {
        await using var stack = await StartAsync();
        var handler = new CapturingHandler(stack.Routes.Clone());
        using var browser = new HttpClient(new CookieJar { InnerHandler = handler }) { BaseAddress = new Uri("https://bff.test/") };
        var account = await stack.TokenServer.CreateAccountAsync();

        var login = await browser.GetAsync(new Uri("bff/login", UriKind.Relative), TestContext.Current.CancellationToken);
        using var authorize = new HttpRequestMessage(HttpMethod.Get, login.Headers.Location);
        authorize.Headers.Add(HeaderSignIn.Header, $"{account.Id}|pwd|{stack.TokenServer.Time.GetUtcNow().ToUnixTimeSeconds()}");
        var code = await browser.SendAsync(authorize, TestContext.Current.CancellationToken);
        await browser.GetAsync(code.Headers.Location, TestContext.Current.CancellationToken);

        var cookie = handler.SetCookies.Where(c => c.StartsWith("__Host-jeffops-session=", StringComparison.Ordinal)).ShouldHaveSingleItem();
        cookie.ShouldContain("httponly", Case.Insensitive);
        cookie.ShouldContain("secure", Case.Insensitive);
        cookie.ShouldContain("samesite=lax", Case.Insensitive);
        cookie.ShouldContain("path=/", Case.Insensitive);
    }

    [Fact]
    public async Task A_state_changing_request_needs_the_csrf_header()
    {
        await using var stack = await StartAsync();
        await SignInAsync(stack);

        (await stack.Browser.PostAsync(new Uri("api/things", UriKind.Relative), null, TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        using var request = new HttpRequestMessage(HttpMethod.Post, "api/things");
        request.Headers.Add("X-JeffOps-Csrf", "1");
        (await stack.Browser.SendAsync(request, TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_bearer_smuggled_next_to_a_dead_session_cookie_is_removed()
    {
        await using var stack = await StartAsync();
        using var client = new HttpClient(stack.Routes.Clone()) { BaseAddress = new Uri("https://bff.test/") };
        var service = await stack.TokenServer.ClientCredentialsAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, "api/whoami");
        request.Headers.Add("Cookie", "__Host-jeffops-session=not-a-session");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", service.AccessToken);

        (await client.SendAsync(request, TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Signing_out_ends_the_session_and_points_to_the_token_servers_end_session()
    {
        await using var stack = await StartAsync();
        await SignInAsync(stack);

        using var logout = new HttpRequestMessage(HttpMethod.Post, "bff/logout");
        logout.Headers.Add("X-JeffOps-Csrf", "1");
        var response = await stack.Browser.SendAsync(logout, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);

        body.GetProperty("endSessionUrl").GetString().ShouldStartWith("https://localhost/connect/endsession?id_token_hint=");
        (await stack.Browser.GetAsync(new Uri("bff/me", UriKind.Relative), TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task An_expiring_access_token_is_refreshed_transparently()
    {
        await using var stack = await StartAsync(accessTokenLifetime: "00:00:20"); // inside the 30 s refresh window: every use refreshes
        var accountId = await SignInAsync(stack);

        for (var i = 0; i < 3; i++)
        {
            var whoami = await stack.Browser.GetFromJsonAsync<JsonElement>(new Uri("api/whoami", UriKind.Relative), TestContext.Current.CancellationToken);
            whoami.GetProperty("user").GetString().ShouldBe(accountId.ToString());
            await Task.Delay(TimeSpan.FromMilliseconds(5500), TestContext.Current.CancellationToken); // past the 5 s local cache
        }
    }

    [Fact]
    public async Task Disabling_an_account_ends_its_bff_sessions_through_back_channel_logout()
    {
        await using var stack = await StartAsync();
        var accountId = await SignInAsync(stack);
        (await stack.Browser.GetAsync(new Uri("bff/me", UriKind.Relative), TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);

        await stack.TokenServer.WithAccountAsync(accountId, account => account.Disable(stack.TokenServer.Time.GetUtcNow()));
        await Task.Delay(TimeSpan.FromMilliseconds(5500), TestContext.Current.CancellationToken); // past the 5 s local cache

        (await stack.Browser.GetAsync(new Uri("bff/me", UriKind.Relative), TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task An_unsigned_or_foreign_logout_token_is_rejected()
    {
        await using var stack = await StartAsync();
        using var client = new HttpClient(stack.Routes.Clone()) { BaseAddress = new Uri("https://bff.test/") };
        var forged = new Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler().CreateToken(
            """{"iss":"https://localhost/","aud":"spa-bff","sub":"x","jti":"1","events":{"http://schemas.openid.net/event/backchannel-logout":{}}}""");

        using var content = new FormUrlEncodedContent(new Dictionary<string, string> { ["logout_token"] = forged });
        (await client.PostAsync(new Uri("bff/backchannel-logout", UriKind.Relative), content, TestContext.Current.CancellationToken))
            .StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    /// <summary>Routes requests to in-process servers by host name; registrations may come after the clone was handed out.</summary>
    private sealed class RoutingHandler
    {
        private readonly Dictionary<string, HttpMessageHandler> _servers = new(StringComparer.OrdinalIgnoreCase);

        public void Add(string host, HttpMessageHandler handler) => _servers[host] = handler;

        public HttpMessageHandler Clone() => new Router(this);

        private sealed class Router(RoutingHandler routes) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                new HttpMessageInvoker(routes._servers[request.RequestUri!.Host], disposeHandler: false).SendAsync(request, cancellationToken);
        }
    }

    private sealed class TestForwarderFactory(RoutingHandler routes) : IForwarderHttpClientFactory
    {
        public HttpMessageInvoker CreateClient(ForwarderHttpClientContext context) => new(routes.Clone());
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

    private sealed class CapturingHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
    {
        public List<string> SetCookies { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = await base.SendAsync(request, cancellationToken);
            SetCookies.AddRange(response.Headers.TryGetValues("Set-Cookie", out var values) ? values : []);
            return response;
        }
    }
}

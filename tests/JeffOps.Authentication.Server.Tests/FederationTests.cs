using System.Net;
using System.Security.Claims;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Federation.Entra;
using JeffOps.Authentication.Federation.Oidc;
using JeffOps.Authentication.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>
/// Federation end to end: a second token server plays the upstream identity provider, and this server signs users in
/// through it with <c>AddOidcProvider</c>, exactly as it would with Okta, Keycloak or Google.
/// </summary>
public sealed class FederationTests
{
    private const string DownstreamSecret = "downstream-secret-that-is-at-least-thirty-two-chars";

    private static Task<TokenServerHost> StartUpstreamAsync() =>
        TokenServerHost.StartAsync(new()
        {
            ["JeffOps:TokenServer:Issuer"] = "https://upstream.test/",
            ["JeffOps:TokenServer:Clients:3:ClientId"] = "downstream",
            ["JeffOps:TokenServer:Clients:3:ClientSecret"] = DownstreamSecret,
            ["JeffOps:TokenServer:Clients:3:GrantTypes:0"] = "authorization_code",
            ["JeffOps:TokenServer:Clients:3:RedirectUris:0"] = "https://localhost/signin/callback/upstream",
            ["JeffOps:TokenServer:Clients:3:Scopes:0"] = "openid",
            ["JeffOps:TokenServer:Clients:3:Scopes:1"] = "profile",
            ["JeffOps:TokenServer:Clients:3:Scopes:2"] = "email",
        });

    private static Task<TokenServerHost> StartDownstreamAsync(TokenServerHost upstream, Dictionary<string, string?>? settings = null)
    {
        var upstreamHandler = upstream.CreateHandler();
        return TokenServerHost.StartAsync(
            new Dictionary<string, string?>(settings ?? new() { ["JeffOps:TokenServer:Federation:OpenRegistration"] = "true" })
            {
                ["JeffOps:TokenServer:Federation:DomainProviders:upstream.example"] = "upstream",
            },
            configure: builder =>
            {
                new Application.DependencyInjection.AuthenticationBuilder(builder.Services, builder.Configuration).AddOidcProvider("upstream", provider =>
                {
                    provider.Authority = new Uri("https://upstream.test/");
                    provider.ClientId = "downstream";
                    provider.ClientSecret = DownstreamSecret;
                    provider.DisplayName = "Upstream IdP";
                });

                // The OpenIddict client's back channel (discovery, token endpoint) goes to the upstream test server.
                builder.Services.PostConfigureAll<HttpClientFactoryOptions>(options =>
                    options.HttpMessageHandlerBuilderActions.Add(handler => handler.PrimaryHandler = upstreamHandler));
            },
            cookieSignIn: true);
    }

    /// <summary>Plays the browser: follows the redirects between the two servers, carrying each one's cookies.</summary>
    private static async Task<HttpResponseMessage> SignInThroughUpstreamAsync(TokenServerHost downstream, TokenServerHost upstream, Browser browser, Guid upstreamAccount, string returnUrl = "/done")
    {
        // 1. Downstream sends the browser to the upstream authorize endpoint.
        var challenge = await browser.GetAsync(downstream, $"signin/upstream?returnUrl={Uri.EscapeDataString(returnUrl)}");
        challenge.StatusCode.ShouldBe(HttpStatusCode.Redirect, await challenge.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        challenge.Headers.Location!.Host.ShouldBe("upstream.test");

        // 2. The user is signed in at the upstream provider, which redirects back with a code.
        using var authorize = new HttpRequestMessage(HttpMethod.Get, challenge.Headers.Location.PathAndQuery);
        authorize.Headers.Add(HeaderSignIn.Header, $"{upstreamAccount}|pwd,mfa|{upstream.Time.GetUtcNow().ToUnixTimeSeconds()}");
        var upstreamResponse = await upstream.Client.SendAsync(authorize, TestContext.Current.CancellationToken);
        upstreamResponse.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        upstreamResponse.Headers.Location!.ToString().ShouldStartWith("https://localhost/signin/callback/upstream");

        // 3. The downstream callback redeems the code, links the account and signs the user in.
        return await browser.GetAsync(downstream, upstreamResponse.Headers.Location.PathAndQuery);
    }

    [Fact]
    public async Task A_first_sign_in_through_an_upstream_provider_creates_and_signs_in_a_linked_account()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream);
        var upstreamAccount = await upstream.CreateAccountAsync("lin@upstream.example");
        using var browser = new Browser(downstream);

        var callback = await SignInThroughUpstreamAsync(downstream, upstream, browser, upstreamAccount.Id);

        callback.StatusCode.ShouldBe(HttpStatusCode.Redirect, await callback.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        callback.Headers.Location!.OriginalString.ShouldBe("/done");

        await using var scope = downstream.Services.CreateAsyncScope();
        var linked = await scope.ServiceProvider.GetRequiredService<IAccountRepository>()
            .FindByExternalLoginAsync(new ExternalLoginKey("https://upstream.test/", upstreamAccount.Id.ToString()), TestContext.Current.CancellationToken);
        linked.ShouldNotBeNull();
        linked.Email.ShouldBe("lin@upstream.example");

        // The sign-in session now completes the normal code flow at the downstream server.
        var (location, _) = await AuthorizeWithBrowserAsync(downstream, browser);
        location.ToString().ShouldStartWith(TokenServerHost.BffRedirect);
    }

    [Fact]
    public async Task A_second_sign_in_reuses_the_linked_account()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream);
        var upstreamAccount = await upstream.CreateAccountAsync("lin@upstream.example");

        using (var first = new Browser(downstream))
        {
            await SignInThroughUpstreamAsync(downstream, upstream, first, upstreamAccount.Id);
        }

        using (var second = new Browser(downstream))
        {
            await SignInThroughUpstreamAsync(downstream, upstream, second, upstreamAccount.Id);
        }

        await using var scope = downstream.Services.CreateAsyncScope();
        (await scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>().Accounts.CountAsync(TestContext.Current.CancellationToken)).ShouldBe(1);
    }

    [Fact]
    public async Task A_domain_outside_the_allow_list_is_sent_back_to_the_login_page()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream, new() { ["JeffOps:TokenServer:Federation:AllowedEmailDomains:0"] = "contoso.com" });
        var upstreamAccount = await upstream.CreateAccountAsync("lin@upstream.example");
        using var browser = new Browser(downstream);

        var callback = await SignInThroughUpstreamAsync(downstream, upstream, browser, upstreamAccount.Id);

        callback.Headers.Location!.OriginalString.ShouldStartWith("/account/login?");
        callback.Headers.Location.OriginalString.ShouldContain("error=domain_not_allowed");
    }

    [Fact]
    public async Task A_return_url_to_another_site_is_ignored()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream);
        var upstreamAccount = await upstream.CreateAccountAsync("lin@upstream.example");
        using var browser = new Browser(downstream);

        var callback = await SignInThroughUpstreamAsync(downstream, upstream, browser, upstreamAccount.Id, returnUrl: "https://evil.example/");

        callback.Headers.Location!.OriginalString.ShouldBe("/");
    }

    [Fact]
    public async Task Home_realm_discovery_sends_a_known_domain_to_its_provider_and_others_to_the_login_page()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream);
        using var browser = new Browser(downstream);

        var known = await browser.GetAsync(downstream, "account/login/discover?email=lin@upstream.example&returnUrl=/x");
        var unknown = await browser.GetAsync(downstream, "account/login/discover?email=someone@elsewhere.example&returnUrl=/x");

        known.Headers.Location!.OriginalString.ShouldStartWith("/signin/upstream?returnUrl=%2Fx&login_hint=");
        unknown.Headers.Location!.OriginalString.ShouldStartWith("/account/login?returnUrl=%2Fx&email=");
    }

    [Fact]
    public async Task An_unknown_provider_is_not_found()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream);

        (await downstream.Client.GetAsync(new Uri("signin/nope", UriKind.Relative), TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task The_login_page_lists_the_providers_and_sends_its_own_strict_policy()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream);

        var response = await downstream.Client.GetAsync(new Uri("account/login?returnUrl=/connect/authorize&error=domain_not_allowed", UriKind.Relative), TestContext.Current.CancellationToken);
        var html = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        html.ShouldContain("Upstream IdP");
        html.ShouldContain("href=\"/signin/upstream?returnUrl=%2Fconnect%2Fauthorize\"");
        html.ShouldContain("Accounts from your organization");
        response.Headers.GetValues("Content-Security-Policy").Single().ShouldContain("default-src 'none'");
    }

    // Two products, each with its own registration at the provider: "time" signs in through "upstream", "tickets" through
    // "tickets-idp" only (not configured here, so nothing can satisfy it).
    private static Dictionary<string, string?> ProductClients() => new()
    {
        ["JeffOps:TokenServer:Federation:OpenRegistration"] = "true",
        ["JeffOps:TokenServer:Clients:3:ClientId"] = "time",
        ["JeffOps:TokenServer:Clients:3:DisplayName"] = "JeffOps Time",
        ["JeffOps:TokenServer:Clients:3:Kind"] = "Public",
        ["JeffOps:TokenServer:Clients:3:GrantTypes:0"] = "authorization_code",
        ["JeffOps:TokenServer:Clients:3:RedirectUris:0"] = "https://time.test/callback",
        ["JeffOps:TokenServer:Clients:3:Scopes:0"] = "openid",
        ["JeffOps:TokenServer:Clients:3:Providers:0"] = "upstream",
        ["JeffOps:TokenServer:Clients:4:ClientId"] = "tickets",
        ["JeffOps:TokenServer:Clients:4:DisplayName"] = "JeffOps Tickets",
        ["JeffOps:TokenServer:Clients:4:Kind"] = "Public",
        ["JeffOps:TokenServer:Clients:4:GrantTypes:0"] = "authorization_code",
        ["JeffOps:TokenServer:Clients:4:RedirectUris:0"] = "https://tickets.test/callback",
        ["JeffOps:TokenServer:Clients:4:Scopes:0"] = "openid",
        ["JeffOps:TokenServer:Clients:4:Providers:0"] = "tickets-idp",
    };

    private static string AuthorizePath(string clientId, string redirectUri) =>
        $"/connect/authorize?client_id={clientId}&response_type=code&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
        "&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGjSstw-cM&code_challenge_method=S256";

    [Fact]
    public async Task The_login_page_names_the_client_and_offers_only_its_providers()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream, ProductClients());

        async Task<string> LoginPageAsync(string returnUrl) =>
            await (await downstream.Client.GetAsync(new Uri($"account/login?returnUrl={Uri.EscapeDataString(returnUrl)}", UriKind.Relative), TestContext.Current.CancellationToken))
                .Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        var time = await LoginPageAsync(AuthorizePath("time", "https://time.test/callback"));
        time.ShouldContain("to continue to JeffOps Time");
        time.ShouldContain("Upstream IdP");

        var tickets = await LoginPageAsync(AuthorizePath("tickets", "https://tickets.test/callback"));
        tickets.ShouldContain("to continue to JeffOps Tickets");
        tickets.ShouldNotContain("Upstream IdP");

        var unlimited = await LoginPageAsync(AuthorizePath(TokenServerHost.BffClient, TokenServerHost.BffRedirect));
        unlimited.ShouldContain("Upstream IdP");
        unlimited.ShouldNotContain("to continue to");
    }

    [Fact]
    public async Task A_sign_in_through_another_products_provider_must_sign_in_again()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream, ProductClients());
        var upstreamAccount = await upstream.CreateAccountAsync("lin@upstream.example");
        using var browser = new Browser(downstream);
        await SignInThroughUpstreamAsync(downstream, upstream, browser, upstreamAccount.Id);

        // Time accepts the sign-in it came through …
        var time = await browser.GetAsync(downstream, AuthorizePath("time", "https://time.test/callback"));
        time.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        time.Headers.Location!.ToString().ShouldStartWith("https://time.test/callback?code=");

        // … Tickets doesn't: the user signs in again, through Tickets' own provider.
        var tickets = await browser.GetAsync(downstream, AuthorizePath("tickets", "https://tickets.test/callback"));
        tickets.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        tickets.Headers.Location!.ToString().ShouldContain("/account/login");

        // With prompt=none there is no one to ask: login_required.
        var silent = await browser.GetAsync(downstream, AuthorizePath("tickets", "https://tickets.test/callback") + "&prompt=none&state=s");
        silent.Headers.Location!.ToString().ShouldStartWith("https://tickets.test/callback?error=login_required");
    }

    [Fact]
    public async Task A_provider_the_client_does_not_accept_is_neither_started_nor_discovered()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream, ProductClients());
        using var browser = new Browser(downstream);
        var tickets = Uri.EscapeDataString(AuthorizePath("tickets", "https://tickets.test/callback"));

        var challenge = await browser.GetAsync(downstream, $"signin/upstream?returnUrl={tickets}");
        challenge.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        challenge.Headers.Location!.OriginalString.ShouldStartWith("/account/login?");
        challenge.Headers.Location.OriginalString.ShouldContain("error=provider_not_allowed");

        // upstream.example maps to "upstream", which Tickets doesn't accept: back to the login page instead.
        var discovered = await browser.GetAsync(downstream, $"account/login/discover?email=lin@upstream.example&returnUrl={tickets}");
        discovered.Headers.Location!.OriginalString.ShouldStartWith("/account/login?");
    }

    [Theory]
    [InlineData("/connect/authorize?response_type=code&client_id=time&scope=openid", "time")]
    [InlineData("/connect/authorize?client_id=a%20b", "a b")]
    [InlineData("/base/connect/authorize?client_id=time", "time")]
    [InlineData("/connect/authorize?scope=openid", null)]
    [InlineData("/account/device?client_id=time", null)]
    [InlineData("/", null)]
    [InlineData(null, null)]
    public void The_client_of_a_sign_in_comes_from_its_authorization_request(string? returnUrl, string? clientId) =>
        ClientProviders.ClientIdOf(returnUrl).ShouldBe(clientId);

    private static async Task<(Uri Location, string Verifier)> AuthorizeWithBrowserAsync(TokenServerHost server, Browser browser)
    {
        var verifier = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var challenge = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var response = await browser.GetAsync(server,
            $"connect/authorize?client_id={TokenServerHost.BffClient}&response_type=code&redirect_uri={Uri.EscapeDataString(TokenServerHost.BffRedirect)}" +
            $"&scope=openid&code_challenge={challenge}&code_challenge_method=S256");
        response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        return (response.Headers.Location!, verifier);
    }
}

public sealed class EntraMapperTests
{
    private static readonly EntraIdentityMapper Mapper = new(
        new ExternalProviderInfo("entra", "Microsoft"),
        Options.Create(new FederationOptions { MultiFactorAuthenticationContexts = { "c1" } }));

    private static ClaimsPrincipal Principal(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(claim => new Claim(claim.Type, claim.Value)), "entra"));

    [Fact]
    public void Entra_users_are_linked_on_tenant_and_object_id()
    {
        var tenant = Guid.NewGuid();
        var objectId = Guid.NewGuid();

        var identity = Mapper.Map("entra", Principal(("tid", tenant.ToString()), ("oid", objectId.ToString()), ("email", "ada@contoso.com"), ("amr", "pwd"))).Value;

        identity.Login.ShouldBe(new ExternalLoginKey($"https://login.microsoftonline.com/{tenant}/v2.0", objectId.ToString()));
        identity.DirectoryId.ShouldBe(tenant.ToString());
        identity.EmailVerified.ShouldBeFalse("Entra's email claim is not verified for every account type");
        identity.Strength.IsMultiFactor.ShouldBeFalse();
    }

    [Fact]
    public void Mfa_comes_from_amr_or_a_configured_authentication_context()
    {
        (string, string)[] ids = [("tid", "t"), ("oid", "o")];

        Mapper.Map("entra", Principal([.. ids, ("amr", "mfa")])).Value.Strength.IsMultiFactor.ShouldBeTrue();
        Mapper.Map("entra", Principal([.. ids, ("acrs", "c1")])).Value.Strength.IsMultiFactor.ShouldBeTrue();
        Mapper.Map("entra", Principal([.. ids, ("acrs", "c2")])).Value.Strength.IsMultiFactor.ShouldBeFalse();
    }

    [Fact]
    public void A_response_without_tid_and_oid_is_refused() =>
        Mapper.Map("entra", Principal(("sub", "x"))).IsFailure.ShouldBeTrue();
}

/// <summary>A minimal browser: one cookie jar per server origin, no automatic redirects.</summary>
internal sealed class Browser : IDisposable
{
    private readonly HttpClient _client;
    private readonly System.Net.CookieContainer _cookies = new();

    public Browser(TokenServerHost server)
    {
        _client = new HttpClient(new CookieHandler(_cookies) { InnerHandler = server.CreateHandler() })
        {
            BaseAddress = new Uri("https://localhost/"),
        };
    }

    public Task<HttpResponseMessage> GetAsync(TokenServerHost server, string pathAndQuery) =>
        _client.GetAsync(new Uri(pathAndQuery.TrimStart('/'), UriKind.Relative), TestContext.Current.CancellationToken);

    public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request) => _client.SendAsync(request, TestContext.Current.CancellationToken);

    /// <summary>Gives <paramref name="other"/> this browser's cookies, as an attacker who stole them would hold them.</summary>
    public void CopyCookiesTo(Browser other)
    {
        ArgumentNullException.ThrowIfNull(other);
        foreach (System.Net.Cookie cookie in _cookies.GetAllCookies())
        {
            other._cookies.Add(cookie);
        }
    }

    public void Dispose() => _client.Dispose();

    private sealed class CookieHandler(System.Net.CookieContainer cookies) : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var header = cookies.GetCookieHeader(request.RequestUri!);
            if (!string.IsNullOrEmpty(header))
            {
                request.Headers.Add("Cookie", header);
            }

            var response = await base.SendAsync(request, cancellationToken);
            if (response.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                foreach (var setCookie in setCookies)
                {
                    cookies.SetCookies(request.RequestUri!, setCookie);
                }
            }

            return response;
        }
    }
}

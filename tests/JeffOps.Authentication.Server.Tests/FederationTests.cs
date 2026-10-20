using System.Net;
using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Domain.Sessions;
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
    public async Task A_first_party_client_receives_the_upstream_identity_and_its_chosen_claims_also_after_a_refresh()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream, new()
        {
            ["JeffOps:TokenServer:Federation:OpenRegistration"] = "true",
            ["JeffOps:TokenServer:Clients:0:ForwardUpstreamIdentity"] = "true",
            ["JeffOps:TokenServer:Clients:0:UpstreamClaims:0"] = "email_verified",
        });
        var upstreamAccount = await upstream.CreateAccountAsync("lin@upstream.example");
        using var browser = new Browser(downstream);

        // The sign-in starts from the client's authorization request, so it knows which claims that client takes.
        var (authorize, verifier) = AuthorizePath("openid offline_access api");
        var callback = await SignInThroughUpstreamAsync(downstream, upstream, browser, upstreamAccount.Id, returnUrl: authorize);
        var code = await browser.GetAsync(downstream, callback.Headers.Location!.OriginalString);
        var tokens = await RedeemAsync(downstream, code.Headers.Location!, verifier);

        tokens.Claims("idp").ShouldBe(["upstream"]);
        tokens.Claims("idp_iss").ShouldBe(["https://upstream.test"]);
        tokens.Claims("idp_sub").ShouldBe([upstreamAccount.Id.ToString()]);
        tokens.Claims("email_verified").ShouldBe(["true"]);
        new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(tokens.IdToken!).Claims.ShouldNotContain(claim => claim.Type.StartsWith("idp", StringComparison.Ordinal), "access tokens only");

        var refreshed = await downstream.RefreshAsync(tokens.RefreshToken!);
        refreshed.Claims("idp_sub").ShouldBe([upstreamAccount.Id.ToString()]);
        refreshed.Claims("email_verified").ShouldBe(["true"]);
    }

    [Fact]
    public async Task An_authentication_context_a_provider_can_t_give_doesn_t_keep_the_user_signing_in()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream);
        var upstreamAccount = await upstream.CreateAccountAsync("lin@upstream.example");
        using var browser = new Browser(downstream);

        // The client asks for c1; the user isn't signed in, so the token server sends them to the provider, asking for c1.
        var (authorize, verifier) = AuthorizePath("openid api");
        var first = await browser.GetAsync(downstream, authorize + "&acr_values=c1");
        var returnUrl = TokenServerHost.QueryValue(new Uri(new Uri("https://localhost/"), first.Headers.Location!), "returnUrl").ShouldNotBeNull();
        returnUrl.ShouldContain("jeffops_acr_values=c1");

        // This provider doesn't report authentication contexts: the client still gets its code, once.
        var callback = await SignInThroughUpstreamAsync(downstream, upstream, browser, upstreamAccount.Id, returnUrl: returnUrl);
        var code = await browser.GetAsync(downstream, callback.Headers.Location!.OriginalString);
        code.Headers.Location!.OriginalString.ShouldStartWith(TokenServerHost.BffRedirect);
        (await RedeemAsync(downstream, code.Headers.Location, verifier)).Access.Claims.ShouldNotContain(claim => claim.Type == "acrs");

        // Signed in through that provider without c1: a new request for it signs the user in again, asking for it.
        var (again, _) = AuthorizePath("openid api");
        var asked = await browser.GetAsync(downstream, again + "&acr_values=c1");
        TokenServerHost.QueryValue(new Uri(new Uri("https://localhost/"), asked.Headers.Location!), "returnUrl").ShouldNotBeNull()
            .ShouldContain("jeffops_acr_values=c1");
    }

    [Fact]
    public async Task Other_clients_receive_nothing_of_the_upstream_identity()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream);
        var upstreamAccount = await upstream.CreateAccountAsync("lin@upstream.example");
        using var browser = new Browser(downstream);

        var (authorize, verifier) = AuthorizePath("openid offline_access api");
        var callback = await SignInThroughUpstreamAsync(downstream, upstream, browser, upstreamAccount.Id, returnUrl: authorize);
        var code = await browser.GetAsync(downstream, callback.Headers.Location!.OriginalString);
        var tokens = await RedeemAsync(downstream, code.Headers.Location!, verifier);

        tokens.Access.Claims.ShouldNotContain(claim => claim.Type == "idp" || claim.Type == "idp_iss" || claim.Type == "idp_sub" || claim.Type == "email_verified");
    }

    [Fact]
    public async Task A_client_can_t_take_this_server_s_own_claims_from_a_provider() =>
        (await Should.ThrowAsync<Microsoft.Extensions.Options.OptionsValidationException>(() => TokenServerHost.StartAsync(new()
        {
            ["JeffOps:TokenServer:Clients:0:UpstreamClaims:0"] = "tid",
        }))).Message.ShouldContain("UpstreamClaims");

    private static (string Path, string Verifier) AuthorizePath(string scope)
    {
        var verifier = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var challenge = Convert.ToBase64String(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return ($"/connect/authorize?client_id={TokenServerHost.BffClient}&response_type=code&redirect_uri={Uri.EscapeDataString(TokenServerHost.BffRedirect)}" +
            $"&scope={Uri.EscapeDataString(scope)}&code_challenge={challenge}&code_challenge_method=S256&state=xyz", verifier);
    }

    private static Task<TokenResponse> RedeemAsync(TokenServerHost server, Uri redirect, string verifier) =>
        server.TokenAsync(new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = TokenServerHost.QueryValue(redirect, "code").ShouldNotBeNull(redirect.ToString()),
            ["redirect_uri"] = TokenServerHost.BffRedirect,
            ["code_verifier"] = verifier,
            ["client_id"] = TokenServerHost.BffClient,
            ["client_secret"] = TokenServerHost.BffSecret,
        });

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
    public async Task The_allow_list_admits_only_emails_the_provider_vouches_for()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream, new() { ["JeffOps:TokenServer:Federation:AllowedEmailDomains:0"] = "contoso.com" });
        var claimed = await upstream.CreateAccountAsync("mallory@contoso.com", emailVerified: false);
        var verified = await upstream.CreateAccountAsync("lin@contoso.com");

        using (var browser = new Browser(downstream))
        {
            var callback = await SignInThroughUpstreamAsync(downstream, upstream, browser, claimed.Id);
            callback.Headers.Location!.OriginalString.ShouldContain("error=domain_not_allowed");
        }

        using (var browser = new Browser(downstream))
        {
            var callback = await SignInThroughUpstreamAsync(downstream, upstream, browser, verified.Id);
            callback.Headers.Location!.OriginalString.ShouldBe("/done");
        }
    }

    [Fact]
    public async Task A_fresh_sign_in_is_asked_of_the_provider_and_an_older_authentication_is_refused()
    {
        await using var upstream = await StartUpstreamAsync();
        await using var downstream = await StartDownstreamAsync(upstream);
        var upstreamAccount = await upstream.CreateAccountAsync("lin@upstream.example");

        // The client asked downstream for prompt=login; the user is already signed in at the upstream provider.
        async Task<HttpResponseMessage> SignInAsync(string returnUrl)
        {
            using var browser = new Browser(downstream);
            using var atUpstream = new Browser(upstream);
            var challenge = await browser.GetAsync(downstream, $"signin/upstream?returnUrl={Uri.EscapeDataString(returnUrl)}");
            var signedIn = $"{upstreamAccount.Id}|pwd,mfa|{upstream.Time.GetUtcNow().AddHours(-1).ToUnixTimeSeconds()}";

            // Upstream got prompt=login (in the pushed request): its older session doesn't do, the user signs in there again.
            using (var authorize = new HttpRequestMessage(HttpMethod.Get, challenge.Headers.Location!.PathAndQuery.TrimStart('/')))
            {
                authorize.Headers.Add(HeaderSignIn.Header, signedIn);
                var asked = await atUpstream.SendAsync(authorize);
                asked.Headers.Location!.OriginalString.ShouldStartWith("/login?returnUrl=", customMessage: "the provider was asked to authenticate the user again");
                challenge = asked;
            }

            var again = Uri.UnescapeDataString(challenge.Headers.Location!.OriginalString["/login?returnUrl=".Length..]);
            using var resumed = new HttpRequestMessage(HttpMethod.Get, again.TrimStart('/'));
            resumed.Headers.Add(HeaderSignIn.Header, $"{upstreamAccount.Id}|pwd,mfa|{upstream.Time.GetUtcNow().ToUnixTimeSeconds()}");
            var code = await atUpstream.SendAsync(resumed);
            code.Headers.Location!.ToString().ShouldStartWith("https://localhost/signin/callback/upstream", customMessage: "the new sign-in answers the pushed request, once");
            return await browser.GetAsync(downstream, code.Headers.Location.PathAndQuery);
        }

        var fresh = $"/done?jeffops_signed_in_after={downstream.Time.GetUtcNow().ToUnixTimeSeconds()}";
        (await SignInAsync(fresh)).Headers.Location!.OriginalString.ShouldBe(fresh);

        // A provider whose authentication time is before the request (here: its clock an hour behind) doesn't count.
        downstream.Time.Advance(TimeSpan.FromHours(1));
        var stale = $"/done?jeffops_signed_in_after={downstream.Time.GetUtcNow().ToUnixTimeSeconds()}";
        (await SignInAsync(stale)).Headers.Location!.OriginalString.ShouldContain("error=reauthentication_required");
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
    public async Task A_client_that_skips_the_login_page_sends_the_user_straight_to_its_provider()
    {
        await using var upstream = await StartUpstreamAsync();
        var clients = ProductClients();
        clients["JeffOps:TokenServer:Clients:3:SkipLoginPage"] = "true";
        await using var downstream = await StartDownstreamAsync(upstream, clients);
        using var browser = new Browser(downstream);
        var authorize = AuthorizePath("time", "https://time.test/callback");

        var first = await browser.GetAsync(downstream, authorize + "&login_hint=lin%40upstream.example");
        first.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        var location = new Uri(new Uri("https://localhost/"), first.Headers.Location!);
        location.AbsolutePath.ShouldBe("/signin/upstream");
        TokenServerHost.QueryValue(location, "returnUrl").ShouldNotBeNull().ShouldStartWith(authorize);
        TokenServerHost.QueryValue(location, "login_hint").ShouldBe("lin@upstream.example");

        // On to the provider, without the login page.
        var challenge = await browser.GetAsync(downstream, first.Headers.Location!.OriginalString);
        challenge.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        challenge.Headers.Location!.Host.ShouldBe("upstream.test");

        // With prompt=none there is still no one to ask: login_required.
        var silent = await browser.GetAsync(downstream, authorize + "&prompt=none&state=s");
        silent.Headers.Location!.ToString().ShouldStartWith("https://time.test/callback?error=login_required");
    }

    [Theory]
    [InlineData(null, null)]
    [InlineData("local", null)]
    [InlineData("upstream", "other")]
    public async Task Only_a_client_with_one_provider_can_skip_the_login_page(string? first, string? second)
    {
        var settings = new Dictionary<string, string?> { ["JeffOps:TokenServer:Clients:0:SkipLoginPage"] = "true" };
        if (first is not null)
        {
            settings["JeffOps:TokenServer:Clients:0:Providers:0"] = first;
        }

        if (second is not null)
        {
            settings["JeffOps:TokenServer:Clients:0:Providers:1"] = second;
        }

        (await Should.ThrowAsync<Microsoft.Extensions.Options.OptionsValidationException>(() => TokenServerHost.StartAsync(settings)))
            .Message.ShouldContain("SkipLoginPage");
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

public sealed class UpstreamIdentityTests
{
    private static readonly ExternalLoginKey Login = new("https://login.microsoftonline.com/0d6f.../v2.0", "1234");

    private static ClaimsPrincipal Provider(params (string Type, string Value)[] claims) =>
        new(new ClaimsIdentity(claims.Select(claim => new Claim(claim.Type, claim.Value)), "entra"));

    [Fact]
    public void Nothing_is_kept_of_a_provider_a_tenant_registered()
    {
        UpstreamIdentity.Capture(TenantProviderNames.OidcPrefix + Guid.NewGuid().ToString("N"), Login, Provider(("groups", "g1")), ["groups"]).ShouldBeEmpty();
        UpstreamIdentity.Capture(TenantProviderNames.Prefix + Guid.NewGuid().ToString("N"), Login, Provider(("groups", "g1")), ["groups"]).ShouldBeEmpty();
    }

    [Fact]
    public void A_client_gets_only_what_it_asked_for_and_never_from_a_local_sign_in()
    {
        var names = ClaimNames.Default;
        var captured = UpstreamIdentity.Capture("entra-time", Login, Provider(("groups", "g1"), ("groups", "g2"), ("wids", "w1"), ("acct", "0")), ["groups", "wids"]);
        var signIn = SignInPrincipal.Create(Guid.NewGuid(), AuthenticationStrength.Password, DateTimeOffset.UtcNow, names, "test", "entra-time", captured);

        var client = new ClientDefinition { ClientId = "time-web", ForwardUpstreamIdentity = true };
        client.UpstreamClaims.Add("groups");
        var forwarded = UpstreamIdentity.FromSignIn(signIn, client, names);
        forwarded.Select(claim => $"{claim.Type}={claim.Value}").ShouldBe(
            ["idp=entra-time", $"idp_iss={Login.Issuer}", $"idp_sub={Login.Subject}", "groups=g1", "groups=g2"], ignoreOrder: true);

        UpstreamIdentity.FromSignIn(signIn, new ClientDefinition { ClientId = "other" }, names).ShouldBeEmpty();
        var local = SignInPrincipal.Create(Guid.NewGuid(), AuthenticationStrength.Password, DateTimeOffset.UtcNow, names, "test", ClientProviders.Local, captured);
        UpstreamIdentity.FromSignIn(local, client, names).ShouldBeEmpty();
    }

    [Fact]
    public void A_sign_in_counts_for_the_contexts_its_provider_reported()
    {
        var captured = UpstreamIdentity.Capture("entra-time", Login, Provider(("acrs", "c1")), AuthenticationContexts.ProviderClaims);
        var signIn = SignInPrincipal.Create(Guid.NewGuid(), AuthenticationStrength.Password, DateTimeOffset.UtcNow, ClaimNames.Default, "test", "entra-time", captured);

        AuthenticationContexts.Satisfied(signIn, ["c1"]).ShouldBeTrue();
        AuthenticationContexts.Satisfied(signIn, ["c1", "c2"]).ShouldBeFalse();
        AuthenticationContexts.Satisfied(SignInPrincipal.Create(Guid.NewGuid(), AuthenticationStrength.Password, DateTimeOffset.UtcNow, ClaimNames.Default, "test"), ["c1"])
            .ShouldBeFalse();

        // Signing in again helps only where a provider whose claims are kept can report the context.
        AuthenticationContexts.Missing(signIn, ["c1"]).ShouldBeFalse();
        AuthenticationContexts.Missing(signIn, ["c2"]).ShouldBeTrue();
        AuthenticationContexts.Missing(signIn, []).ShouldBeFalse();
        foreach (var provider in new[] { ClientProviders.Local, TenantProviderNames.OidcPrefix + Guid.NewGuid().ToString("N"), null })
        {
            AuthenticationContexts.Missing(SignInPrincipal.Create(Guid.NewGuid(), AuthenticationStrength.Password, DateTimeOffset.UtcNow, ClaimNames.Default, "test", provider), ["c1"])
                .ShouldBeFalse(provider);
        }
    }

    [Fact]
    public void Acr_values_are_read_strictly_and_asked_of_entra_as_its_claims_parameter()
    {
        AuthenticationContexts.Parse("c1 c2 c1").ShouldBe(["c1", "c2"]);
        AuthenticationContexts.Parse("c1 <script>").ShouldBeEmpty();
        AuthenticationContexts.Parse(string.Join(' ', Enumerable.Range(1, 6).Select(i => "c" + i))).ShouldBeEmpty("at most five");

        AuthenticationContexts.EntraClaimsParameter(["c1"]).ShouldBe("""{"id_token":{"acrs":{"essential":true,"value":"c1"}}}""");
        AuthenticationContexts.EntraClaimsParameter(["c1", "c2"]).ShouldBe("""{"id_token":{"acrs":{"essential":true,"values":["c1","c2"]}}}""");
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("tid")]
    [InlineData("email")]
    [InlineData("act")]
    [InlineData("idp_sub")]
    [InlineData("jeffops:idp")]
    public void This_server_s_own_claims_are_reserved(string type) => UpstreamIdentity.IsReserved(type, ClaimNames.Default).ShouldBeTrue();
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
    public void An_Entra_email_counts_as_verified_only_with_a_verified_domain_owner()
    {
        var tenant = Guid.NewGuid().ToString();
        var objectId = Guid.NewGuid().ToString();

        Mapper.Map("entra", Principal(("tid", tenant), ("oid", objectId), ("email", "ada@contoso.com"), ("xms_edov", "true"))).Value.EmailVerified.ShouldBeTrue();
        Mapper.Map("entra", Principal(("tid", tenant), ("oid", objectId), ("email", "ada@contoso.com"), ("xms_edov", "false"))).Value.EmailVerified.ShouldBeFalse();
        Mapper.Map("entra", Principal(("tid", tenant), ("oid", objectId), ("preferred_username", "ada@contoso.com"), ("xms_edov", "true"))).Value.EmailVerified.ShouldBeFalse();
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

    /// <summary>The user goes to <paramref name="pathAndQuery"/> from this site itself (a link or the address bar).</summary>
    public async Task<HttpResponseMessage> NavigateAsync(string pathAndQuery)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(pathAndQuery.TrimStart('/'), UriKind.Relative));
        request.Headers.Add("Sec-Fetch-Site", "same-origin");
        return await _client.SendAsync(request, TestContext.Current.CancellationToken);
    }

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

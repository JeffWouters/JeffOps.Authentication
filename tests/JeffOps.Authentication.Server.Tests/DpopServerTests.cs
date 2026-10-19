using System.Net;
using System.Text.Json;

namespace JeffOps.Authentication.Server.Tests;

public sealed class DpopServerTests
{
    private const string TokenUrl = "https://localhost/connect/token";
    private const string DpopClient = "dpop-svc";
    private const string DpopSecret = "dpop-svc-secret-that-is-at-least-thirty-two-chars";

    [Fact]
    public async Task A_client_that_requires_dpop_gets_key_bound_tokens_and_proofs_work_once()
    {
        await using var host = await StartAsync();
        using var key = new DpopKey();
        var form = new Dictionary<string, string> { ["grant_type"] = "client_credentials", ["client_id"] = DpopClient, ["client_secret"] = DpopSecret, ["scope"] = "api" };

        (await TokenAsync(host, form, proof: null)).Error.ShouldBe("invalid_dpop_proof");

        var proof = key.Proof("POST", TokenUrl);
        var bound = await TokenAsync(host, form, proof);
        bound.Status.ShouldBe(HttpStatusCode.OK, bound.Body.ToString());
        bound.Body.GetProperty("token_type").GetString().ShouldBe("DPoP");
        bound.Access.GetPayloadValue<JsonElement>("cnf").GetProperty("jkt").GetString().ShouldBe(key.Thumbprint);

        (await TokenAsync(host, form, proof)).Error.ShouldBe("invalid_dpop_proof");
    }

    [Fact]
    public async Task A_refresh_token_issued_with_dpop_needs_the_same_key()
    {
        await using var host = await StartAsync();
        using var key = new DpopKey();
        using var thief = new DpopKey();
        var account = await host.CreateAccountAsync();

        var (location, verifier) = await host.AuthorizeAsync(account.Id, scope: "openid offline_access api");
        var code = TokenServerHost.QueryValue(location, "code")!;
        var issued = await TokenAsync(host, new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TokenServerHost.BffRedirect,
            ["code_verifier"] = verifier,
            ["client_id"] = TokenServerHost.BffClient,
            ["client_secret"] = TokenServerHost.BffSecret,
        }, key.Proof("POST", TokenUrl));
        issued.Status.ShouldBe(HttpStatusCode.OK, issued.Body.ToString());
        issued.Claims("jeffops_dpop_jkt").ShouldBeEmpty("the binding claim stays out of access tokens");

        var refresh = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = issued.RefreshToken!,
            ["client_id"] = TokenServerHost.BffClient,
            ["client_secret"] = TokenServerHost.BffSecret,
        };
        (await TokenAsync(host, refresh, thief.Proof("POST", TokenUrl))).Error.ShouldBe("invalid_dpop_proof");
        (await TokenAsync(host, refresh, proof: null)).Error.ShouldBe("invalid_dpop_proof");

        var renewed = await TokenAsync(host, refresh, key.Proof("POST", TokenUrl));
        renewed.Status.ShouldBe(HttpStatusCode.OK, renewed.Body.ToString());
        renewed.Access.GetPayloadValue<JsonElement>("cnf").GetProperty("jkt").GetString().ShouldBe(key.Thumbprint);
    }

    [Fact]
    public async Task With_server_nonces_a_proof_must_carry_a_recent_nonce_from_this_server()
    {
        await using var host = await TokenServerHost.StartAsync(new()
        {
            ["JeffOps:TokenServer:RequireDpopNonce"] = "true",
            ["JeffOps:TokenServer:Clients:3:ClientId"] = DpopClient,
            ["JeffOps:TokenServer:Clients:3:ClientSecret"] = DpopSecret,
            ["JeffOps:TokenServer:Clients:3:GrantTypes:0"] = "client_credentials",
            ["JeffOps:TokenServer:Clients:3:Scopes:0"] = "api",
        });
        using var key = new DpopKey();
        var form = new Dictionary<string, string> { ["grant_type"] = "client_credentials", ["client_id"] = DpopClient, ["client_secret"] = DpopSecret, ["scope"] = "api" };

        var (first, nonce) = await TokenWithNonceAsync(host, form, key.Proof("POST", TokenUrl));
        first.Error.ShouldBe("use_dpop_nonce");
        nonce.ShouldNotBeNull();

        var (second, next) = await TokenWithNonceAsync(host, form, key.Proof("POST", TokenUrl, nonce: nonce));
        second.Status.ShouldBe(HttpStatusCode.OK, second.Body.ToString());
        next.ShouldNotBeNull();

        host.Time.Advance(TimeSpan.FromMinutes(6));
        (await TokenWithNonceAsync(host, form, key.Proof("POST", TokenUrl, issuedAt: host.Time.GetUtcNow(), nonce: next))).Response.Error.ShouldBe("use_dpop_nonce");
        (await TokenWithNonceAsync(host, form, key.Proof("POST", TokenUrl, issuedAt: host.Time.GetUtcNow(), nonce: "forged"))).Response.Error.ShouldBe("use_dpop_nonce");
    }

    [Fact]
    public async Task A_code_requested_with_dpop_jkt_is_redeemable_only_with_that_key()
    {
        await using var host = await StartAsync();
        using var key = new DpopKey();
        using var thief = new DpopKey();
        var account = await host.CreateAccountAsync();

        async Task<TokenResponse> RedeemAsync(string? proof)
        {
            var (location, verifier) = await host.AuthorizeAsync(account.Id, scope: "openid api", extra: $"&dpop_jkt={key.Thumbprint}");
            return await TokenAsync(host, new()
            {
                ["grant_type"] = "authorization_code",
                ["code"] = TokenServerHost.QueryValue(location, "code")!,
                ["redirect_uri"] = TokenServerHost.BffRedirect,
                ["code_verifier"] = verifier,
                ["client_id"] = TokenServerHost.BffClient,
                ["client_secret"] = TokenServerHost.BffSecret,
            }, proof);
        }

        (await RedeemAsync(proof: null)).Error.ShouldBe("invalid_dpop_proof");
        (await RedeemAsync(thief.Proof("POST", TokenUrl))).Error.ShouldBe("invalid_dpop_proof");
        var redeemed = await RedeemAsync(key.Proof("POST", TokenUrl));
        redeemed.Status.ShouldBe(HttpStatusCode.OK, redeemed.Body.ToString());
        redeemed.Access.GetPayloadValue<JsonElement>("cnf").GetProperty("jkt").GetString().ShouldBe(key.Thumbprint);
    }

    [Fact]
    public async Task Discovery_lists_the_accepted_proof_algorithms()
    {
        await using var host = await StartAsync();

        var json = await host.Client.GetStringAsync(new Uri(".well-known/openid-configuration", UriKind.Relative), TestContext.Current.CancellationToken);

        JsonDocument.Parse(json).RootElement.GetProperty("dpop_signing_alg_values_supported").EnumerateArray().Select(value => value.GetString()).ShouldContain("ES256");
    }

    [Fact]
    public async Task The_server_s_own_apis_need_the_proof_of_a_bound_token()
    {
        await using var host = await StartAsync();
        using var key = new DpopKey();
        var token = (await BoundSessionAsync(host, key)).AccessToken!;

        (await host.SendAsync(HttpMethod.Get, "account/pats", token)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "a bound token sent as a bearer token");
        (await SendDpopAsync(host, "account/pats", token, proof: null)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        var proof = key.Proof("GET", "https://localhost/account/pats", token);
        (await SendDpopAsync(host, "account/pats", token, proof)).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await SendDpopAsync(host, "account/pats", token, proof)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized, "proofs work once");

        using var thief = new DpopKey();
        (await SendDpopAsync(host, "account/pats", token, thief.Proof("GET", "https://localhost/account/pats", token))).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        (await host.SendAsync(HttpMethod.Get, "connect/userinfo", token)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        var userInfo = await SendDpopAsync(host, "connect/userinfo", token, key.Proof("GET", "https://localhost/connect/userinfo", token));
        userInfo.StatusCode.ShouldBe(HttpStatusCode.OK, await userInfo.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task A_revoked_access_token_stops_working_at_once()
    {
        await using var host = await StartAsync();
        var account = await host.CreateAccountAsync();
        var token = (await host.SignInAsync(account.Id)).AccessToken!;
        (await host.SendAsync(HttpMethod.Get, "account/pats", token)).StatusCode.ShouldBe(HttpStatusCode.OK);

        var revoked = await host.Client.PostAsync(new Uri("connect/revoke", UriKind.Relative), new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = token,
            ["client_id"] = TokenServerHost.BffClient,
            ["client_secret"] = TokenServerHost.BffSecret,
        }), TestContext.Current.CancellationToken);
        revoked.StatusCode.ShouldBe(HttpStatusCode.OK);

        (await host.SendAsync(HttpMethod.Get, "account/pats", token)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    private static async Task<TokenResponse> BoundSessionAsync(TokenServerHost host, DpopKey key)
    {
        var account = await host.CreateAccountAsync();
        var (location, verifier) = await host.AuthorizeAsync(account.Id, scope: "openid account");
        var issued = await TokenAsync(host, new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = TokenServerHost.QueryValue(location, "code")!,
            ["redirect_uri"] = TokenServerHost.BffRedirect,
            ["code_verifier"] = verifier,
            ["client_id"] = TokenServerHost.BffClient,
            ["client_secret"] = TokenServerHost.BffSecret,
        }, key.Proof("POST", TokenUrl));
        issued.Status.ShouldBe(HttpStatusCode.OK, issued.Body.ToString());
        return issued;
    }

    private static async Task<HttpResponseMessage> SendDpopAsync(TokenServerHost host, string path, string token, string? proof)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("DPoP", token);
        if (proof is not null)
        {
            request.Headers.Add("DPoP", proof);
        }

        return await host.Client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static Task<TokenServerHost> StartAsync() => TokenServerHost.StartAsync(new()
    {
        ["JeffOps:TokenServer:Clients:3:ClientId"] = DpopClient,
        ["JeffOps:TokenServer:Clients:3:ClientSecret"] = DpopSecret,
        ["JeffOps:TokenServer:Clients:3:GrantTypes:0"] = "client_credentials",
        ["JeffOps:TokenServer:Clients:3:Scopes:0"] = "api",
        ["JeffOps:TokenServer:Clients:3:RequireDpop"] = "true",
    });

    private static async Task<(TokenResponse Response, string? Nonce)> TokenWithNonceAsync(TokenServerHost host, Dictionary<string, string> form, string proof)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "connect/token") { Content = new FormUrlEncodedContent(form) };
        request.Headers.Add("DPoP", proof);
        var response = await host.Client.SendAsync(request, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var nonce = response.Headers.TryGetValues("DPoP-Nonce", out var values) ? values.Single() : null;
        return (new TokenResponse(response.StatusCode, JsonDocument.Parse(body).RootElement.Clone()), nonce);
    }

    private static async Task<TokenResponse> TokenAsync(TokenServerHost host, Dictionary<string, string> form, string? proof)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "connect/token") { Content = new FormUrlEncodedContent(form) };
        if (proof is not null)
        {
            request.Headers.Add("DPoP", proof);
        }

        var response = await host.Client.SendAsync(request, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        return new TokenResponse(response.StatusCode, JsonDocument.Parse(body).RootElement.Clone());
    }
}

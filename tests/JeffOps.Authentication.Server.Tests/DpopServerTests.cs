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
    public async Task Discovery_lists_the_accepted_proof_algorithms()
    {
        await using var host = await StartAsync();

        var json = await host.Client.GetStringAsync(new Uri(".well-known/openid-configuration", UriKind.Relative), TestContext.Current.CancellationToken);

        JsonDocument.Parse(json).RootElement.GetProperty("dpop_signing_alg_values_supported").EnumerateArray().Select(value => value.GetString()).ShouldContain("ES256");
    }

    private static Task<TokenServerHost> StartAsync() => TokenServerHost.StartAsync(new()
    {
        ["JeffOps:TokenServer:Clients:3:ClientId"] = DpopClient,
        ["JeffOps:TokenServer:Clients:3:ClientSecret"] = DpopSecret,
        ["JeffOps:TokenServer:Clients:3:GrantTypes:0"] = "client_credentials",
        ["JeffOps:TokenServer:Clients:3:Scopes:0"] = "api",
        ["JeffOps:TokenServer:Clients:3:RequireDpop"] = "true",
    });

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

using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JeffOps.Authentication.Server.Tests;

public sealed partial class HardeningTests
{
    private const string JwtClient = "jwt-svc";
    private const string DeviceClient = "tv-app";
    private const string ParClient = "par-app";
    private const string ParSecret = "par-app-secret-that-is-at-least-thirty-two-characters";
    private const string ParRedirect = "https://par.test/callback";

    [Fact]
    public async Task A_client_authenticates_with_a_signed_assertion_instead_of_a_secret()
    {
        using var key = RSA.Create(2048);
        await using var host = await StartAsync(JwksOf(key));

        var accepted = await host.TokenAsync(new()
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = JwtClient,
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = Assertion(key, "https://localhost/"),
            ["scope"] = "api",
        });
        accepted.Status.ShouldBe(HttpStatusCode.OK, accepted.Body.ToString());
        accepted.Claims("sub").ShouldBe([JwtClient]);

        using var other = RSA.Create(2048);
        var refused = await host.TokenAsync(new()
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = JwtClient,
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = Assertion(other, "https://localhost/"),
            ["scope"] = "api",
        });
        refused.Error.ShouldBe("invalid_client");
    }

    [Fact]
    public async Task A_client_assertion_authenticates_one_request_only()
    {
        using var key = RSA.Create(2048);
        await using var host = await StartAsync(JwksOf(key));
        var assertion = Assertion(key, "https://localhost/");
        Dictionary<string, string> Request(string clientAssertion) => new()
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = JwtClient,
            ["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ["client_assertion"] = clientAssertion,
            ["scope"] = "api",
        };

        (await host.TokenAsync(Request(assertion))).Status.ShouldBe(HttpStatusCode.OK);
        (await host.TokenAsync(Request(assertion))).Error.ShouldBe("invalid_client", "replayed");
        (await host.TokenAsync(Request(Assertion(key, "https://localhost/", jti: null)))).Error.ShouldBe("invalid_client", "no jti to remember it by");
    }

    [Fact]
    public async Task A_client_that_requires_par_must_push_its_authorization_requests()
    {
        await using var host = await StartAsync();
        var account = await host.CreateAccountAsync();
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        using (var direct = new HttpRequestMessage(HttpMethod.Get,
            $"connect/authorize?client_id={ParClient}&response_type=code&redirect_uri={Uri.EscapeDataString(ParRedirect)}&scope=openid&code_challenge={challenge}&code_challenge_method=S256"))
        {
            direct.Headers.Add(HeaderSignIn.Header, $"{account.Id}|pwd,mfa|{host.Time.GetUtcNow().ToUnixTimeSeconds()}");
            var refused = await host.Client.SendAsync(direct, TestContext.Current.CancellationToken);
            refused.StatusCode.ShouldNotBe(HttpStatusCode.Redirect, "an unpushed request must not reach the redirect URI with a code");
        }

        using var pushed = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = ParClient,
            ["client_secret"] = ParSecret,
            ["response_type"] = "code",
            ["redirect_uri"] = ParRedirect,
            ["scope"] = "openid",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
        });
        var par = await host.Client.PostAsync(new Uri("connect/par", UriKind.Relative), pushed, TestContext.Current.CancellationToken);
        par.StatusCode.ShouldBe(HttpStatusCode.Created, await par.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var requestUri = JsonDocument.Parse(await par.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).RootElement.GetProperty("request_uri").GetString()!;

        using var authorize = new HttpRequestMessage(HttpMethod.Get, $"connect/authorize?client_id={ParClient}&request_uri={Uri.EscapeDataString(requestUri)}");
        authorize.Headers.Add(HeaderSignIn.Header, $"{account.Id}|pwd,mfa|{host.Time.GetUtcNow().ToUnixTimeSeconds()}");
        var redirect = await host.Client.SendAsync(authorize, TestContext.Current.CancellationToken);
        redirect.StatusCode.ShouldBe(HttpStatusCode.Redirect, await redirect.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        TokenServerHost.QueryValue(redirect.Headers.Location!, "code").ShouldNotBeNull(redirect.Headers.Location!.ToString());
    }

    [Fact]
    public async Task A_dpop_proof_at_the_pushed_request_binds_the_code_to_its_key()
    {
        await using var host = await StartAsync();
        var account = await host.CreateAccountAsync();
        using var key = new DpopKey();
        using var thief = new DpopKey();
        var verifier = Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        using var push = new HttpRequestMessage(HttpMethod.Post, "connect/par")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = ParClient,
                ["client_secret"] = ParSecret,
                ["response_type"] = "code",
                ["redirect_uri"] = ParRedirect,
                ["scope"] = "openid",
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = "S256",
            }),
        };
        push.Headers.Add("DPoP", key.Proof("POST", "https://localhost/connect/par"));
        var par = await host.Client.SendAsync(push, TestContext.Current.CancellationToken);
        par.StatusCode.ShouldBe(HttpStatusCode.Created, await par.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var requestUri = JsonDocument.Parse(await par.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).RootElement.GetProperty("request_uri").GetString()!;

        using var authorize = new HttpRequestMessage(HttpMethod.Get, $"connect/authorize?client_id={ParClient}&request_uri={Uri.EscapeDataString(requestUri)}");
        authorize.Headers.Add(HeaderSignIn.Header, $"{account.Id}|pwd,mfa|{host.Time.GetUtcNow().ToUnixTimeSeconds()}");
        var code = TokenServerHost.QueryValue((await host.Client.SendAsync(authorize, TestContext.Current.CancellationToken)).Headers.Location!, "code")!;

        Dictionary<string, string> Redeem() => new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = ParRedirect,
            ["code_verifier"] = verifier,
            ["client_id"] = ParClient,
            ["client_secret"] = ParSecret,
        };
        (await RedeemAsync(host, Redeem(), proof: null)).ShouldContain("invalid_dpop_proof", Case.Sensitive, "the code is bound to the pushed proof's key");
        (await RedeemAsync(host, Redeem(), thief.Proof("POST", "https://localhost/connect/token"))).ShouldContain("invalid_dpop_proof");
        JsonDocument.Parse(await RedeemAsync(host, Redeem(), key.Proof("POST", "https://localhost/connect/token")))
            .RootElement.GetProperty("token_type").GetString().ShouldBe("DPoP");
    }

    private static async Task<string> RedeemAsync(TokenServerHost host, Dictionary<string, string> form, string? proof)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "connect/token") { Content = new FormUrlEncodedContent(form) };
        if (proof is not null)
        {
            request.Headers.Add("DPoP", proof);
        }

        return await (await host.Client.SendAsync(request, TestContext.Current.CancellationToken)).Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
    }

    [Fact]
    public async Task A_device_gets_tokens_after_its_user_approves_on_another_screen()
    {
        await using var host = await StartAsync();
        var account = await host.CreateAccountAsync();

        var started = await PostFormAsync(host, "connect/device", new() { ["client_id"] = DeviceClient, ["scope"] = "openid api" });
        var deviceCode = started.GetProperty("device_code").GetString()!;
        var userCode = started.GetProperty("user_code").GetString()!;
        started.GetProperty("verification_uri").GetString()!.ShouldEndWith("/connect/verify");

        var pending = await host.TokenAsync(new() { ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code", ["device_code"] = deviceCode, ["client_id"] = DeviceClient });
        pending.Error.ShouldBe("authorization_pending");

        // On the phone: open the verification page signed in, see the client's name, allow.
        using var phone = new Browser(host);
        var signIn = $"{account.Id}|pwd,mfa|{host.Time.GetUtcNow().ToUnixTimeSeconds()}";
        var verify = await SendAsync(phone, HttpMethod.Get, $"connect/verify?user_code={Uri.EscapeDataString(userCode)}", signIn);
        verify.Headers.Location!.OriginalString.ShouldContain("consent=");
        var page = await (await SendAsync(phone, HttpMethod.Get, verify.Headers.Location.OriginalString, signIn)).Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        page.ShouldContain("<strong>TV</strong>");

        var approve = await SendAsync(phone, HttpMethod.Post, "connect/verify", signIn, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = AntiforgeryToken().Match(page).Groups[1].Value,
            ["user_code"] = userCode,
            ["consent"] = System.Net.WebUtility.HtmlDecode(ConsentField().Match(page).Groups[1].Value),
            ["decision"] = "approve",
        }));
        approve.Headers.Location!.OriginalString.ShouldContain("result=approved");

        var tokens = await host.TokenAsync(new() { ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code", ["device_code"] = deviceCode, ["client_id"] = DeviceClient });
        tokens.Status.ShouldBe(HttpStatusCode.OK, tokens.Body.ToString());
        tokens.Claims("sub").ShouldBe([account.Id.ToString()]);
    }

    [Fact]
    public async Task A_device_client_limited_to_some_providers_isn_t_approved_with_another_sign_in()
    {
        await using var host = await StartAsync(extra: new() { ["JeffOps:TokenServer:Clients:3:Providers:0"] = "corp" });
        var account = await host.CreateAccountAsync();
        var started = await PostFormAsync(host, "connect/device", new() { ["client_id"] = DeviceClient, ["scope"] = "openid api" });
        var deviceCode = started.GetProperty("device_code").GetString()!;
        var userCode = started.GetProperty("user_code").GetString()!;

        // Signed in on the phone some other way than through "corp".
        using var phone = new Browser(host);
        var signIn = $"{account.Id}|pwd,mfa|{host.Time.GetUtcNow().ToUnixTimeSeconds()}";
        var verify = await SendAsync(phone, HttpMethod.Get, $"connect/verify?user_code={Uri.EscapeDataString(userCode)}", signIn);
        var page = await (await SendAsync(phone, HttpMethod.Get, verify.Headers.Location!.OriginalString, signIn)).Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var approve = await SendAsync(phone, HttpMethod.Post, "connect/verify", signIn, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = AntiforgeryToken().Match(page).Groups[1].Value,
            ["user_code"] = userCode,
            ["consent"] = System.Net.WebUtility.HtmlDecode(ConsentField().Match(page).Groups[1].Value),
            ["decision"] = "approve",
        }));

        approve.Headers.Location!.OriginalString.ShouldContain("error=provider_not_allowed");
        (await host.TokenAsync(new() { ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code", ["device_code"] = deviceCode, ["client_id"] = DeviceClient }))
            .Error.ShouldBe("authorization_pending");
    }

    [Fact]
    public async Task The_device_confirmation_names_only_the_code_s_own_client()
    {
        await using var host = await StartAsync();
        var account = await host.CreateAccountAsync();
        var started = await PostFormAsync(host, "connect/device", new() { ["client_id"] = DeviceClient, ["scope"] = "openid api" });
        var deviceCode = started.GetProperty("device_code").GetString()!;
        var userCode = started.GetProperty("user_code").GetString()!;
        using var phone = new Browser(host);
        var signIn = $"{account.Id}|pwd,mfa|{host.Time.GetUtcNow().ToUnixTimeSeconds()}";

        // A phishing link naming a trusted application: the page doesn't show that name.
        var spoofed = await (await SendAsync(phone, HttpMethod.Get, $"account/device?user_code={Uri.EscapeDataString(userCode)}&client=Microsoft%20Teams", signIn))
            .Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        spoofed.ShouldNotContain("Microsoft Teams");

        // Approving without the server's consent ticket shows the real confirmation again instead.
        var approve = await SendAsync(phone, HttpMethod.Post, "connect/verify", signIn, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = AntiforgeryToken().Match(spoofed).Groups[1].Value,
            ["user_code"] = userCode,
            ["decision"] = "approve",
        }));
        approve.Headers.Location!.OriginalString.ShouldNotContain("result=approved");
        (await host.TokenAsync(new() { ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code", ["device_code"] = deviceCode, ["client_id"] = DeviceClient }))
            .Error.ShouldBe("authorization_pending");
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private static Task<TokenServerHost> StartAsync(string? jwks = null, Dictionary<string, string?>? extra = null)
    {
        var settings = new Dictionary<string, string?>
        {
            ["JeffOps:TokenServer:Clients:3:ClientId"] = DeviceClient,
            ["JeffOps:TokenServer:Clients:3:DisplayName"] = "TV",
            ["JeffOps:TokenServer:Clients:3:Kind"] = "Public",
            ["JeffOps:TokenServer:Clients:3:GrantTypes:0"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["JeffOps:TokenServer:Clients:3:Scopes:0"] = "openid",
            ["JeffOps:TokenServer:Clients:3:Scopes:1"] = "api",

            ["JeffOps:TokenServer:Clients:4:ClientId"] = ParClient,
            ["JeffOps:TokenServer:Clients:4:ClientSecret"] = ParSecret,
            ["JeffOps:TokenServer:Clients:4:GrantTypes:0"] = "authorization_code",
            ["JeffOps:TokenServer:Clients:4:RedirectUris:0"] = ParRedirect,
            ["JeffOps:TokenServer:Clients:4:Scopes:0"] = "openid",
            ["JeffOps:TokenServer:Clients:4:RequirePushedAuthorization"] = "true",
        };
        if (jwks is not null)
        {
            settings["JeffOps:TokenServer:Clients:5:ClientId"] = JwtClient;
            settings["JeffOps:TokenServer:Clients:5:JsonWebKeySet"] = jwks;
            settings["JeffOps:TokenServer:Clients:5:GrantTypes:0"] = "client_credentials";
            settings["JeffOps:TokenServer:Clients:5:Scopes:0"] = "api";
        }

        foreach (var (key, value) in extra ?? [])
        {
            settings[key] = value;
        }

        return TokenServerHost.StartAsync(settings);
    }

    private static string JwksOf(RSA key)
    {
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(new RsaSecurityKey(key.ExportParameters(false)) { KeyId = "k1" });
        return JsonSerializer.Serialize(new { keys = new[] { new { kty = jwk.Kty, kid = jwk.Kid, n = jwk.N, e = jwk.E, use = "sig", alg = "RS256" } } });
    }

    private static string Assertion(RSA key, string audience, string? jti = "") =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = JwtClient,
            Audience = audience,
            Subject = new ClaimsIdentity(jti is null
                ? [new Claim("sub", JwtClient)]
                : [new Claim("sub", JwtClient), new Claim("jti", jti.Length == 0 ? Guid.NewGuid().ToString() : jti)]),
            Expires = DateTime.UtcNow.AddMinutes(2),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(key) { KeyId = "k1" }, SecurityAlgorithms.RsaSha256),
            TokenType = "client-authentication+jwt",
        });

    private static async Task<JsonElement> PostFormAsync(TokenServerHost host, string path, Dictionary<string, string> form)
    {
        using var content = new FormUrlEncodedContent(form);
        var response = await host.Client.PostAsync(new Uri(path, UriKind.Relative), content, TestContext.Current.CancellationToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        response.IsSuccessStatusCode.ShouldBeTrue(body);
        return JsonDocument.Parse(body).RootElement.Clone();
    }

    private static Task<HttpResponseMessage> SendAsync(Browser browser, HttpMethod method, string path, string signIn, HttpContent? content = null)
    {
        var request = new HttpRequestMessage(method, path.TrimStart('/')) { Content = content };
        request.Headers.Add(HeaderSignIn.Header, signIn);
        return browser.SendAsync(request);
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [GeneratedRegex("<input[^>]*name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();

    [GeneratedRegex("name=\"consent\" value=\"([^\"]*)\"")]
    private static partial Regex ConsentField();
}

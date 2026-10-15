using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JeffOps.Authentication.Server.Tests;

public sealed class WorkloadIdentityTests : IDisposable
{
    private const string Ci = "https://ci.test/";
    private const string Branch = "repo:contoso/app:ref:refs/heads/main";
    private const string Audience = "jeffops";
    private const string GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    private readonly RSA _ciKey = RSA.Create(2048);

    [Fact]
    public async Task A_workload_trades_its_platform_token_for_the_client_s_service_token()
    {
        await using var host = await StartAsync();

        var tokens = await ExchangeAsync(host, Token(_ciKey, Branch, Audience));

        tokens.Status.ShouldBe(HttpStatusCode.OK, tokens.Body.ToString());
        tokens.Claims("sub").ShouldBe(["deployer"]);
        tokens.Claims("lvl").ShouldBe(["Service"]);
        tokens.Claims("perm").ShouldBe(["deploy.*"]);
        tokens.RefreshToken.ShouldBeNull();
    }

    [Fact]
    public async Task Only_the_trusted_subject_audience_issuer_and_lifetime_are_accepted()
    {
        await using var host = await StartAsync();
        using var stranger = RSA.Create(2048);

        (await ExchangeAsync(host, Token(_ciKey, "repo:contoso/app:pull_request", Audience))).Code.ShouldBe("token_invalid");
        (await ExchangeAsync(host, Token(_ciKey, Branch, "someone-else"))).Code.ShouldBe("token_invalid");
        (await ExchangeAsync(host, Token(stranger, Branch, Audience))).Code.ShouldBe("token_invalid");
        (await ExchangeAsync(host, Token(_ciKey, Branch, Audience, expires: DateTime.UtcNow.AddMinutes(-5)))).Code.ShouldBe("token_invalid");
        (await ExchangeAsync(host, Token(_ciKey, Branch, Audience), clientId: TokenServerHost.GatewayClient, secret: TokenServerHost.GatewaySecret)).Error.ShouldNotBeNull();
    }

    public void Dispose() => _ciKey.Dispose();

    private Task<TokenServerHost> StartAsync() => TokenServerHost.StartAsync(
        new()
        {
            ["JeffOps:TokenServer:Clients:3:ClientId"] = "deployer",
            ["JeffOps:TokenServer:Clients:3:Kind"] = "Public",
            ["JeffOps:TokenServer:Clients:3:GrantTypes:0"] = GrantType,
            ["JeffOps:TokenServer:Clients:3:Scopes:0"] = "api",
            ["JeffOps:TokenServer:Clients:3:ServicePermissions:0"] = "deploy.*",
            ["JeffOps:TokenServer:Clients:3:FederatedCredentials:0:Issuer"] = Ci,
            ["JeffOps:TokenServer:Clients:3:FederatedCredentials:0:Subject"] = Branch,
            ["JeffOps:TokenServer:Clients:3:FederatedCredentials:0:Audience"] = Audience,
        },
        configure: builder => builder.Services.AddHttpClient("JeffOps.WorkloadIdentity").ConfigurePrimaryHttpMessageHandler(() => new FakeIssuer(_ciKey)));

    private static Task<TokenResponse> ExchangeAsync(TokenServerHost host, string assertion, string clientId = "deployer", string? secret = null)
    {
        var form = new Dictionary<string, string> { ["grant_type"] = GrantType, ["client_id"] = clientId, ["assertion"] = assertion, ["scope"] = "api" };
        if (secret is not null)
        {
            form["client_secret"] = secret;
        }

        return host.TokenAsync(form);
    }

    private static string Token(RSA key, string subject, string audience, DateTime? expires = null) =>
        new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Ci,
            Audience = audience,
            Subject = new ClaimsIdentity([new Claim("sub", subject)]),
            NotBefore = (expires ?? DateTime.UtcNow.AddMinutes(5)).AddMinutes(-10),
            IssuedAt = (expires ?? DateTime.UtcNow.AddMinutes(5)).AddMinutes(-10),
            Expires = expires ?? DateTime.UtcNow.AddMinutes(5),
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(key) { KeyId = "ci-1" }, SecurityAlgorithms.RsaSha256),
        });

    /// <summary>The CI system's issuer: a discovery document and its keys.</summary>
    private sealed class FakeIssuer(RSA key) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            object? body = path switch
            {
                "/.well-known/openid-configuration" => new { issuer = Ci, jwks_uri = "https://ci.test/jwks" },
                "/jwks" => new { keys = new[] { Jwk() } },
                _ => null,
            };

            return Task.FromResult(body is null
                ? new HttpResponseMessage(HttpStatusCode.NotFound)
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") });
        }

        private object Jwk()
        {
            var parameters = key.ExportParameters(false);
            return new { kty = "RSA", kid = "ci-1", use = "sig", alg = "RS256", n = Base64UrlEncoder.Encode(parameters.Modulus), e = Base64UrlEncoder.Encode(parameters.Exponent) };
        }
    }
}

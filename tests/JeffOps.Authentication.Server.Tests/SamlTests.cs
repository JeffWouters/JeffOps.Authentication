using System.Collections.Specialized;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Federation.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace JeffOps.Authentication.Server.Tests;

public sealed class SamlTests : IAsyncDisposable
{
    private const string IdpEntityId = "https://idp.test/";
    private const string MultiFactor = "http://schemas.microsoft.com/claims/multipleauthn";

    private readonly X509Certificate2 _idpCertificate = SelfSigned("CN=Test IdP");
    private TokenServerHost _host = null!;

    [Fact]
    public async Task A_user_signs_in_through_a_saml_provider_with_multi_factor()
    {
        await StartAsync();
        using var browser = new Browser(_host);

        var (requestId, acs, spEntityId) = await StartSignInAsync(browser);
        var response = await PostResponseAsync(browser, Response(requestId, acs, spEntityId, MultiFactor, _idpCertificate));

        response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        response.Headers.Location!.OriginalString.ShouldBe("/done");

        var tokens = await AuthorizeAsync(browser);
        tokens.Claims("amr").ShouldBe(["pwd", "mfa"], ignoreOrder: true);
        tokens.Claims("email").ShouldBe(["jo@corp.test"]);
    }

    [Fact]
    public async Task A_response_signed_by_someone_else_is_refused()
    {
        await StartAsync();
        using var browser = new Browser(_host);
        using var impostor = SelfSigned("CN=Impostor");

        var (requestId, acs, spEntityId) = await StartSignInAsync(browser);
        var response = await PostResponseAsync(browser, Response(requestId, acs, spEntityId, null, impostor));

        response.Headers.Location!.OriginalString.ShouldContain("error=provider_error");
    }

    [Fact]
    public async Task A_response_only_counts_in_the_browser_that_asked_for_it()
    {
        await StartAsync();
        using var victim = new Browser(_host);
        using var attacker = new Browser(_host);

        var (requestId, acs, spEntityId) = await StartSignInAsync(victim);
        var forged = await PostResponseAsync(attacker, Response(requestId, acs, spEntityId, null, _idpCertificate));
        forged.Headers.Location!.OriginalString.ShouldContain("error=signin_expired");

        // An answer to a different request, even signed correctly, is refused too.
        await StartSignInAsync(victim);
        var unsolicited = await PostResponseAsync(victim, Response("_" + Guid.NewGuid().ToString("N"), acs, spEntityId, null, _idpCertificate));
        unsolicited.Headers.Location!.OriginalString.ShouldContain("error=provider_error");
    }

    [Fact]
    public async Task The_provider_gets_this_server_s_metadata()
    {
        await StartAsync();

        var metadata = await _host.Client.GetStringAsync(new Uri("signin/saml/corp/metadata", UriKind.Relative), TestContext.Current.CancellationToken);

        metadata.ShouldContain("entityID=\"https://localhost/signin/saml/corp\"");
        metadata.ShouldContain("Location=\"https://localhost/signin/saml/corp/acs\"");
    }

    public async ValueTask DisposeAsync()
    {
        _idpCertificate.Dispose();
        if (_host is not null)
        {
            await _host.DisposeAsync();
        }
    }

    // ---- The test identity provider -------------------------------------------------------------------------------------

    private async Task StartAsync()
    {
        _host = await TokenServerHost.StartAsync(
            new()
            {
                ["JeffOps:TokenServer:Federation:OpenRegistration"] = "true",
                ["JeffOps:TokenServer:Federation:Saml:corp:DisplayName"] = "Corp",
                ["JeffOps:TokenServer:Federation:Saml:corp:IdpEntityId"] = IdpEntityId,
                ["JeffOps:TokenServer:Federation:Saml:corp:IdpSingleSignOnUrl"] = "https://idp.test/sso",
                ["JeffOps:TokenServer:Federation:Saml:corp:IdpSigningCertificates:0"] = Convert.ToBase64String(_idpCertificate.RawData),
                ["JeffOps:TokenServer:Federation:Saml:corp:MultiFactorAuthnContexts:0"] = MultiFactor,
            },
            configure: builder => new AuthenticationBuilder(builder.Services, builder.Configuration).AddSamlProvider("corp"),
            cookieSignIn: true,
            map: app => app.MapJeffOpsSaml());
    }

    /// <summary>Follows the login page's provider link to the AuthnRequest, and reads it as the provider would.</summary>
    private static async Task<(string RequestId, Uri Acs, string SpEntityId)> StartSignInAsync(Browser browser)
    {
        var challenge = await browser.GetAsync(null!, "signin/corp?returnUrl=%2Fdone");
        challenge.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        var start = await browser.GetAsync(null!, challenge.Headers.Location!.OriginalString);
        start.StatusCode.ShouldBe(HttpStatusCode.Redirect, await start.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var location = start.Headers.Location!;
        location.GetLeftPart(UriPartial.Path).ShouldBe("https://idp.test/sso");

        var query = System.Web.HttpUtility.ParseQueryString(location.Query);
        var request = new Saml2AuthnRequest(new Saml2Configuration { Issuer = IdpEntityId });
        new Saml2RedirectBinding().ReadSamlRequest(
            new ITfoxtec.Identity.Saml2.Http.HttpRequest { Method = "GET", Query = query, QueryString = location.Query, Form = new NameValueCollection() },
            request);
        return (request.IdAsString, request.AssertionConsumerServiceUrl, request.Issuer);
    }

    private static string Response(string inResponseTo, Uri acs, string audience, string? authnContext, X509Certificate2 signer)
    {
        var configuration = new Saml2Configuration { Issuer = IdpEntityId, SigningCertificate = signer };
        var response = new Saml2AuthnResponse(configuration)
        {
            InResponseTo = new Saml2Id(inResponseTo),
            Status = Saml2StatusCodes.Success,
            Destination = acs,
            NameId = new Saml2NameIdentifier("employee-4711", new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")),
            ClaimsIdentity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "employee-4711"),
                new Claim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "jo@corp.test"),
                new Claim("http://schemas.microsoft.com/identity/claims/displayname", "Jo Corp"),
            ]),
        };
        response.CreateSecurityToken(audience, new Uri(authnContext ?? AuthnContextClassTypes.PasswordProtectedTransport.OriginalString), null, 5, 60);

        var binding = new Saml2PostBinding();
        binding.Bind(response);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(binding.XmlDocument.OuterXml));
    }

    private static Task<HttpResponseMessage> PostResponseAsync(Browser browser, string samlResponse) =>
        browser.SendAsync(new HttpRequestMessage(HttpMethod.Post, "signin/saml/corp/acs")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["SAMLResponse"] = samlResponse }),
        });

    private async Task<TokenResponse> AuthorizeAsync(Browser browser)
    {
        var verifier = SoftwareAuthenticator.Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = SoftwareAuthenticator.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var authorize = await browser.GetAsync(null!,
            $"connect/authorize?client_id={TokenServerHost.BffClient}&response_type=code&redirect_uri={Uri.EscapeDataString(TokenServerHost.BffRedirect)}" +
            $"&scope={Uri.EscapeDataString("openid api")}&code_challenge={challenge}&code_challenge_method=S256&state=xyz");
        var code = TokenServerHost.QueryValue(authorize.Headers.Location!, "code").ShouldNotBeNull(authorize.Headers.Location!.ToString());
        return await _host.TokenAsync(new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TokenServerHost.BffRedirect,
            ["code_verifier"] = verifier,
            ["client_id"] = TokenServerHost.BffClient,
            ["client_secret"] = TokenServerHost.BffSecret,
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

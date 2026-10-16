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

    [Fact]
    public async Task With_a_signing_certificate_authn_requests_are_signed_and_published()
    {
        using var serviceProvider = SelfSigned("CN=Token Server");
        await StartAsync(new()
        {
            ["JeffOps:TokenServer:Federation:Saml:corp:SigningCertificatePfx"] = Convert.ToBase64String(serviceProvider.Export(X509ContentType.Pfx)),
        });
        using var browser = new Browser(_host);

        var challenge = await browser.GetAsync(null!, "signin/corp?returnUrl=%2Fdone");
        var start = await browser.GetAsync(null!, challenge.Headers.Location!.OriginalString);
        var location = start.Headers.Location!;
        System.Web.HttpUtility.ParseQueryString(location.Query)["Signature"].ShouldNotBeNullOrEmpty();

        // The provider checks the signature with the published certificate.
        using var published = X509CertificateLoader.LoadCertificate(serviceProvider.RawData);
        var verifying = new Saml2Configuration { Issuer = IdpEntityId };
        verifying.SignatureValidationCertificates.Add(published);
        var request = new Saml2AuthnRequest(verifying);
        new Saml2RedirectBinding().Unbind(
            new ITfoxtec.Identity.Saml2.Http.HttpRequest
            {
                Method = "GET",
                Query = System.Web.HttpUtility.ParseQueryString(location.Query),
                QueryString = location.Query,
                Form = new NameValueCollection(),
            },
            request);

        var metadata = await _host.Client.GetStringAsync(new Uri("signin/saml/corp/metadata", UriKind.Relative), TestContext.Current.CancellationToken);
        metadata.ShouldContain("AuthnRequestsSigned=\"true\"");
        metadata.ShouldContain(Convert.ToBase64String(serviceProvider.RawData));
        metadata.ShouldContain("Location=\"https://localhost/signin/saml/corp/slo\"");
    }

    [Fact]
    public async Task Single_logout_from_the_provider_ends_every_session_of_the_user()
    {
        await StartAsync(new() { ["JeffOps:TokenServer:Federation:Saml:corp:IdpSingleLogoutUrl"] = "https://idp.test/slo" });
        using var browser = new Browser(_host);
        var (requestId, acs, spEntityId) = await StartSignInAsync(browser);
        await PostResponseAsync(browser, Response(requestId, acs, spEntityId, null, _idpCertificate));
        var tokens = await AuthorizeAsync(browser, "openid offline_access api");
        tokens.RefreshToken.ShouldNotBeNull();

        var logout = await _host.Client.GetAsync(LogoutRequest("employee-4711", _idpCertificate), TestContext.Current.CancellationToken);

        logout.StatusCode.ShouldBe(HttpStatusCode.Redirect, await logout.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        logout.Headers.Location!.GetLeftPart(UriPartial.Path).ShouldBe("https://idp.test/slo");
        System.Web.HttpUtility.ParseQueryString(logout.Headers.Location.Query)["SAMLResponse"].ShouldNotBeNullOrEmpty();
        (await _host.RefreshAsync(tokens.RefreshToken)).Error.ShouldBe("invalid_grant");
    }

    [Fact]
    public async Task An_unsigned_or_forged_logout_request_changes_nothing()
    {
        await StartAsync();
        using var browser = new Browser(_host);
        using var impostor = SelfSigned("CN=Impostor");
        var (requestId, acs, spEntityId) = await StartSignInAsync(browser);
        await PostResponseAsync(browser, Response(requestId, acs, spEntityId, null, _idpCertificate));
        var tokens = await AuthorizeAsync(browser, "openid offline_access api");

        (await _host.Client.GetAsync(LogoutRequest("employee-4711", null), TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await _host.Client.GetAsync(LogoutRequest("employee-4711", impostor), TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        // The POST binding too, even when the word "Signature" appears in the request.
        var unsigned = new Saml2LogoutRequest(new Saml2Configuration { Issuer = IdpEntityId, SingleLogoutDestination = new Uri("https://localhost/signin/saml/corp/slo") })
        {
            NameId = new Saml2NameIdentifier("employee-4711", new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")),
            SessionIndex = "Signature",
        };
        var post = new Saml2PostBinding();
        post.Bind(unsigned);
        var posted = await _host.Client.PostAsync(new Uri("signin/saml/corp/slo", UriKind.Relative), new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["SAMLRequest"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(post.XmlDocument.OuterXml)),
        }), TestContext.Current.CancellationToken);
        posted.StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        (await _host.RefreshAsync(tokens.RefreshToken!)).AccessToken.ShouldNotBeNull();
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

    private async Task StartAsync(Dictionary<string, string?>? extra = null)
    {
        var settings = new Dictionary<string, string?>
        {
                ["JeffOps:TokenServer:Federation:OpenRegistration"] = "true",
                ["JeffOps:TokenServer:Federation:Saml:corp:DisplayName"] = "Corp",
                ["JeffOps:TokenServer:Federation:Saml:corp:IdpEntityId"] = IdpEntityId,
                ["JeffOps:TokenServer:Federation:Saml:corp:IdpSingleSignOnUrl"] = "https://idp.test/sso",
                ["JeffOps:TokenServer:Federation:Saml:corp:IdpSigningCertificates:0"] = Convert.ToBase64String(_idpCertificate.RawData),
                ["JeffOps:TokenServer:Federation:Saml:corp:MultiFactorAuthnContexts:0"] = MultiFactor,
        };
        foreach (var (key, value) in extra ?? [])
        {
            settings[key] = value;
        }

        _host = await TokenServerHost.StartAsync(
            settings,
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

    /// <summary>A LogoutRequest from the provider (HTTP-Redirect binding), signed by <paramref name="signer"/> if given.</summary>
    private static Uri LogoutRequest(string nameId, X509Certificate2? signer)
    {
        var configuration = new Saml2Configuration
        {
            Issuer = IdpEntityId,
            SigningCertificate = signer,
            SingleLogoutDestination = new Uri("https://localhost/signin/saml/corp/slo"),
        };
        var request = new Saml2LogoutRequest(configuration)
        {
            NameId = new Saml2NameIdentifier(nameId, new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")),
        };
        var binding = new Saml2RedirectBinding();
        binding.Bind(request);
        return new Uri(binding.RedirectLocation.PathAndQuery.TrimStart('/'), UriKind.Relative);
    }

    private static Task<HttpResponseMessage> PostResponseAsync(Browser browser, string samlResponse) =>
        browser.SendAsync(new HttpRequestMessage(HttpMethod.Post, "signin/saml/corp/acs")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["SAMLResponse"] = samlResponse }),
        });

    private async Task<TokenResponse> AuthorizeAsync(Browser browser, string scope = "openid api")
    {
        var verifier = SoftwareAuthenticator.Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = SoftwareAuthenticator.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var authorize = await browser.GetAsync(null!,
            $"connect/authorize?client_id={TokenServerHost.BffClient}&response_type=code&redirect_uri={Uri.EscapeDataString(TokenServerHost.BffRedirect)}" +
            $"&scope={Uri.EscapeDataString(scope)}&code_challenge={challenge}&code_challenge_method=S256&state=xyz");
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

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
using Microsoft.Extensions.DependencyInjection;
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
    public async Task A_signed_assertion_can_t_be_rewrapped_to_answer_another_browser_s_request()
    {
        await StartAsync();
        using var victim = new Browser(_host);
        using var attacker = new Browser(_host);
        var (victimRequest, acs, spEntityId) = await StartSignInAsync(victim);
        var (attackerRequest, _, _) = await StartSignInAsync(attacker);

        // Only the assertion is signed, as ADFS and Entra send it by default; the Response around it is not. The attacker
        // points the unsigned InResponseTo at their own request.
        var document = AssertionSignedResponse(victimRequest, acs, spEntityId);
        document.DocumentElement!.SetAttribute("InResponseTo", attackerRequest);
        var rewrapped = await PostResponseAsync(attacker, Convert.ToBase64String(Encoding.UTF8.GetBytes(document.OuterXml)));

        rewrapped.Headers.Location!.OriginalString.ShouldContain("error=provider_error");
    }

    [Fact]
    public async Task A_response_with_only_its_assertion_signed_is_accepted()
    {
        await StartAsync();
        using var browser = new Browser(_host);
        var (requestId, acs, spEntityId) = await StartSignInAsync(browser);

        var response = await PostResponseAsync(browser, Convert.ToBase64String(Encoding.UTF8.GetBytes(AssertionSignedResponse(requestId, acs, spEntityId).OuterXml)));

        response.Headers.Location!.OriginalString.ShouldBe("/done");
    }

    [Fact]
    public async Task Transient_name_ids_are_refused()
    {
        await StartAsync();
        using var browser = new Browser(_host);
        var (requestId, acs, spEntityId) = await StartSignInAsync(browser);

        var response = await PostResponseAsync(browser, Response(requestId, acs, spEntityId, null, _idpCertificate, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"));

        response.Headers.Location!.OriginalString.ShouldContain("error=provider_error");
    }

    [Fact]
    public async Task A_return_url_with_control_characters_falls_back_to_the_root()
    {
        await StartAsync();
        using var browser = new Browser(_host);
        // Straight to the SAML endpoint: a slash, a tab and /evil.test would reach a browser as //evil.test.
        var start = await browser.GetAsync(null!, "signin/saml/corp?returnUrl=%2F%09%2Fevil.test");
        var query = System.Web.HttpUtility.ParseQueryString(start.Headers.Location!.Query);
        var request = new Saml2AuthnRequest(new Saml2Configuration { Issuer = IdpEntityId });
        new Saml2RedirectBinding().ReadSamlRequest(
            new ITfoxtec.Identity.Saml2.Http.HttpRequest { Method = "GET", Query = query, QueryString = start.Headers.Location.Query, Form = new NameValueCollection() },
            request);
        var signedIn = await PostResponseAsync(browser, Response(request.IdAsString, request.AssertionConsumerServiceUrl, request.Issuer, null, _idpCertificate));

        signedIn.Headers.Location!.OriginalString.ShouldBe("/");
    }

    [Fact]
    public async Task Encrypted_assertions_are_decrypted_and_can_be_required()
    {
        using var decryption = SelfSigned("CN=Token Server Encryption");
        await StartAsync(new()
        {
            ["JeffOps:TokenServer:Federation:Saml:corp:DecryptionCertificatePfx"] = Convert.ToBase64String(decryption.Export(X509ContentType.Pfx)),
            ["JeffOps:TokenServer:Federation:Saml:corp:RequireEncryptedAssertions"] = "true",
        });
        using var publicPart = X509CertificateLoader.LoadCertificate(decryption.RawData);

        using (var browser = new Browser(_host))
        {
            var (requestId, acs, spEntityId) = await StartSignInAsync(browser);
            var plain = await PostResponseAsync(browser, Response(requestId, acs, spEntityId, null, _idpCertificate));
            plain.Headers.Location!.OriginalString.ShouldContain("error=provider_error", customMessage: "an unencrypted assertion is refused");
        }

        using (var browser = new Browser(_host))
        {
            var (requestId, acs, spEntityId) = await StartSignInAsync(browser);
            var encrypted = Response(requestId, acs, spEntityId, null, _idpCertificate, encryptFor: publicPart);
            Encoding.UTF8.GetString(Convert.FromBase64String(encrypted)).ShouldContain("EncryptedAssertion");

            var signedIn = await PostResponseAsync(browser, encrypted);
            signedIn.Headers.Location!.OriginalString.ShouldBe("/done");
        }

        var metadata = await _host.Client.GetStringAsync(new Uri("signin/saml/corp/metadata", UriKind.Relative), TestContext.Current.CancellationToken);
        metadata.ShouldContain("use=\"encryption\"");
        metadata.ShouldContain(Convert.ToBase64String(decryption.RawData));
    }

    [Fact]
    public async Task Signing_out_here_signs_out_at_the_provider_too_and_comes_back()
    {
        using var serviceProvider = SelfSigned("CN=Token Server");
        await StartAsync(new()
        {
            ["JeffOps:TokenServer:Federation:Saml:corp:IdpSingleLogoutUrl"] = "https://idp.test/slo",
            ["JeffOps:TokenServer:Federation:Saml:corp:SigningCertificatePfx"] = Convert.ToBase64String(serviceProvider.Export(X509ContentType.Pfx)),
        });
        using var browser = new Browser(_host);
        var (requestId, acs, spEntityId) = await StartSignInAsync(browser);
        await PostResponseAsync(browser, Response(requestId, acs, spEntityId, null, _idpCertificate));

        // Signing out at the token server sends the browser to the provider with a LogoutRequest this server signed.
        var signOut = await browser.GetAsync(null!, "connect/endsession");
        signOut.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        var toProvider = signOut.Headers.Location!;
        toProvider.GetLeftPart(UriPartial.Path).ShouldBe("https://idp.test/slo");

        using var spPublic = X509CertificateLoader.LoadCertificate(serviceProvider.RawData);
        var verifying = new Saml2Configuration
        {
            Issuer = IdpEntityId,
            CertificateValidationMode = System.ServiceModel.Security.X509CertificateValidationMode.None, // pinned below, self-signed
            RevocationMode = X509RevocationMode.NoCheck,
        };
        verifying.SignatureValidationCertificates.Add(spPublic);
        var logoutRequest = new Saml2LogoutRequest(verifying);
        var query = System.Web.HttpUtility.ParseQueryString(toProvider.Query);
        var received = new Saml2RedirectBinding();
        received.Unbind(new ITfoxtec.Identity.Saml2.Http.HttpRequest { Method = "GET", Query = query, QueryString = toProvider.Query, Form = new NameValueCollection() }, logoutRequest);
        logoutRequest.NameId.Value.ShouldBe("employee-4711");

        // The provider signs the user out and answers; the browser comes back to finish the end-session request.
        var answer = new Saml2LogoutResponse(new Saml2Configuration { Issuer = IdpEntityId, SigningCertificate = _idpCertificate })
        {
            InResponseTo = logoutRequest.Id,
            Status = Saml2StatusCodes.Success,
            Destination = new Uri("https://localhost/signin/saml/corp/slo"),
        };
        var reply = new Saml2RedirectBinding { RelayState = received.RelayState };
        reply.Bind(answer);
        var back = await browser.GetAsync(null!, reply.RedirectLocation.PathAndQuery.TrimStart('/'));
        back.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        back.Headers.Location!.OriginalString.ShouldStartWith("/connect/endsession");

        var finished = await browser.GetAsync(null!, back.Headers.Location.OriginalString.TrimStart('/'));
        finished.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        finished.Headers.Location!.OriginalString.ShouldNotContain("idp.test", customMessage: "signed out here already, the second pass completes");
    }

    [Fact]
    public async Task A_provider_can_be_configured_by_its_metadata_alone()
    {
        await StartAsync(metadataXml: IdpMetadata(IdpEntityId, _idpCertificate));
        using var browser = new Browser(_host);

        var (requestId, acs, spEntityId) = await StartSignInAsync(browser);   // the sign-in URL came from the metadata
        var response = await PostResponseAsync(browser, Response(requestId, acs, spEntityId, null, _idpCertificate));

        response.Headers.Location!.OriginalString.ShouldBe("/done", "the signing certificate came from the metadata");
    }

    [Fact]
    public async Task Metadata_naming_another_entity_is_not_trusted()
    {
        await StartAsync(
            new() { ["JeffOps:TokenServer:Federation:Saml:corp:IdpSingleSignOnUrl"] = "https://idp.test/sso" },
            metadataXml: IdpMetadata("https://impostor.test/", _idpCertificate));
        using var browser = new Browser(_host);

        var (requestId, acs, spEntityId) = await StartSignInAsync(browser);
        var response = await PostResponseAsync(browser, Response(requestId, acs, spEntityId, null, _idpCertificate));

        response.Headers.Location!.OriginalString.ShouldContain("error=provider_error", customMessage: "no certificate is trusted for the provider");
    }

    private static string IdpMetadata(string entityId, X509Certificate2 signing) => $"""
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entityId}">
          <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:KeyDescriptor use="signing">
              <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{Convert.ToBase64String(signing.RawData)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
            </md:KeyDescriptor>
            <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/slo"/>
            <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/>
          </md:IDPSSODescriptor>
        </md:EntityDescriptor>
        """;

    /// <summary>The identity provider's metadata endpoint.</summary>
    private sealed class MetadataServer(string xml) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(request.RequestUri!.AbsoluteUri == "https://idp.test/metadata"
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(xml, Encoding.UTF8, "application/samlmetadata+xml") }
                : new HttpResponseMessage(HttpStatusCode.NotFound));
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
        _host.Time.Advance(TimeSpan.FromSeconds(5));

        var logout = await _host.Client.GetAsync(LogoutRequest("employee-4711", _idpCertificate), TestContext.Current.CancellationToken);

        logout.StatusCode.ShouldBe(HttpStatusCode.Redirect, await logout.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        logout.Headers.Location!.GetLeftPart(UriPartial.Path).ShouldBe("https://idp.test/slo");
        System.Web.HttpUtility.ParseQueryString(logout.Headers.Location.Query)["SAMLResponse"].ShouldNotBeNullOrEmpty();
        (await _host.RefreshAsync(tokens.RefreshToken)).Error.ShouldBe("invalid_grant");

        // The browser's sign-in here ended with it: it can't get new codes without signing in again.
        var again = await browser.GetAsync(null!,
            $"connect/authorize?client_id={TokenServerHost.BffClient}&response_type=code&redirect_uri={Uri.EscapeDataString(TokenServerHost.BffRedirect)}" +
            $"&scope=openid&code_challenge={SoftwareAuthenticator.Base64Url(SHA256.HashData("verifier"u8))}&code_challenge_method=S256&state=xyz");
        again.Headers.Location!.OriginalString.ShouldContain("account/login");
    }

    [Fact]
    public async Task A_logout_request_works_once_and_only_at_its_destination()
    {
        await StartAsync();
        using var browser = new Browser(_host);
        var (requestId, acs, spEntityId) = await StartSignInAsync(browser);
        await PostResponseAsync(browser, Response(requestId, acs, spEntityId, null, _idpCertificate));

        var elsewhere = LogoutRequest("employee-4711", _idpCertificate, destination: new Uri("https://other-sp.test/slo"));
        var misdirected = new Uri("signin/saml/corp/slo" + elsewhere.OriginalString[elsewhere.OriginalString.IndexOf('?', StringComparison.Ordinal)..], UriKind.Relative);
        (await _host.Client.GetAsync(misdirected, TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        var logout = LogoutRequest("employee-4711", _idpCertificate);
        (await _host.Client.GetAsync(logout, TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await _host.Client.GetAsync(logout, TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.BadRequest, "replayed");
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

    private async Task StartAsync(Dictionary<string, string?>? extra = null, string? metadataXml = null)
    {
        var settings = new Dictionary<string, string?>
        {
                ["JeffOps:TokenServer:Federation:OpenRegistration"] = "true",
                ["JeffOps:TokenServer:Federation:Saml:corp:DisplayName"] = "Corp",
                ["JeffOps:TokenServer:Federation:Saml:corp:IdpEntityId"] = IdpEntityId,
                ["JeffOps:TokenServer:Federation:Saml:corp:MultiFactorAuthnContexts:0"] = MultiFactor,
        };
        if (metadataXml is null)
        {
            settings["JeffOps:TokenServer:Federation:Saml:corp:IdpSingleSignOnUrl"] = "https://idp.test/sso";
            settings["JeffOps:TokenServer:Federation:Saml:corp:IdpSigningCertificates:0"] = Convert.ToBase64String(_idpCertificate.RawData);
        }
        else
        {
            // Everything about the provider comes from its metadata.
            settings["JeffOps:TokenServer:Federation:Saml:corp:IdpMetadataUrl"] = "https://idp.test/metadata";
        }

        foreach (var (key, value) in extra ?? [])
        {
            settings[key] = value;
        }

        _host = await TokenServerHost.StartAsync(
            settings,
            configure: builder =>
            {
                new AuthenticationBuilder(builder.Services, builder.Configuration).AddSamlProvider("corp");
                if (metadataXml is not null)
                {
                    builder.Services.AddHttpClient("JeffOps.Saml.Metadata").ConfigurePrimaryHttpMessageHandler(() => new MetadataServer(metadataXml));
                }
            },
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

    private static string Response(
        string inResponseTo, Uri acs, string audience, string? authnContext, X509Certificate2? signer,
        string nameIdFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", X509Certificate2? encryptFor = null)
    {
        var configuration = new Saml2Configuration { Issuer = IdpEntityId, SigningCertificate = signer, EncryptionCertificate = encryptFor };
        var response = new Saml2AuthnResponse(configuration)
        {
            InResponseTo = new Saml2Id(inResponseTo),
            Status = Saml2StatusCodes.Success,
            Destination = acs,
            NameId = new Saml2NameIdentifier("employee-4711", new Uri(nameIdFormat)),
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
    private static Uri LogoutRequest(string nameId, X509Certificate2? signer, Uri? destination = null)
    {
        var configuration = new Saml2Configuration
        {
            Issuer = IdpEntityId,
            SigningCertificate = signer,
            SingleLogoutDestination = destination ?? new Uri("https://localhost/signin/saml/corp/slo"),
        };
        var request = new Saml2LogoutRequest(configuration)
        {
            NameId = new Saml2NameIdentifier(nameId, new Uri("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")),
        };
        var binding = new Saml2RedirectBinding();
        binding.Bind(request);
        return new Uri(binding.RedirectLocation.PathAndQuery.TrimStart('/'), UriKind.Relative);
    }

    /// <summary>A response whose assertion alone carries the provider's signature.</summary>
    private System.Xml.XmlDocument AssertionSignedResponse(string inResponseTo, Uri acs, string audience)
    {
        var document = new System.Xml.XmlDocument { PreserveWhitespace = true };
        document.LoadXml(Encoding.UTF8.GetString(Convert.FromBase64String(Response(inResponseTo, acs, audience, null, signer: null))));
        var assertion = (System.Xml.XmlElement)document.GetElementsByTagName("Assertion", "urn:oasis:names:tc:SAML:2.0:assertion")[0]!;

        var signed = new System.Security.Cryptography.Xml.SignedXml(document) { SigningKey = _idpCertificate.GetRSAPrivateKey() };
        signed.SignedInfo!.CanonicalizationMethod = System.Security.Cryptography.Xml.SignedXml.XmlDsigExcC14NTransformUrl;
        signed.SignedInfo.SignatureMethod = System.Security.Cryptography.Xml.SignedXml.XmlDsigRSASHA256Url;
        var reference = new System.Security.Cryptography.Xml.Reference("#" + assertion.GetAttribute("ID")) { DigestMethod = System.Security.Cryptography.Xml.SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new System.Security.Cryptography.Xml.XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new System.Security.Cryptography.Xml.XmlDsigExcC14NTransform());
        signed.AddReference(reference);
        signed.KeyInfo = new System.Security.Cryptography.Xml.KeyInfo();
        signed.KeyInfo.AddClause(new System.Security.Cryptography.Xml.KeyInfoX509Data(_idpCertificate));
        signed.ComputeSignature();

        var issuer = assertion.GetElementsByTagName("Issuer", "urn:oasis:names:tc:SAML:2.0:assertion")[0]!;
        assertion.InsertAfter(document.ImportNode(signed.GetXml(), deep: true), issuer);
        return document;
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

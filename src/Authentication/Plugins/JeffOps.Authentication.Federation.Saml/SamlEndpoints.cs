using System.Collections.Specialized;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Claims;
using ITfoxtec.Identity.Saml2.Schemas;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Abstractions.Replay;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Features.Federation.CompleteExternalSignIn;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.SharedKernel.Handlers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace JeffOps.Authentication.Federation.Saml;

/// <summary>
/// The SAML 2.0 service provider endpoints: <c>signin/saml/{provider}</c> sends an AuthnRequest (HTTP-Redirect),
/// <c>signin/saml/{provider}/acs</c> receives the response (HTTP-POST), <c>signin/saml/{provider}/metadata</c> describes this
/// server to the provider. Only SP-initiated sign-ins are accepted: the response must answer a request this browser made.
/// </summary>
public static partial class SamlEndpoints
{
    /// <summary>The route prefix of the SAML endpoints: <c>signin/saml</c>.</summary>
    public const string Prefix = "signin/saml";
    private const string LoginPath = "/account/login";

    /// <summary>
    /// Maps the sign-in, assertion consumer and metadata endpoints under <see cref="Prefix"/> for every provider added with
    /// <c>AddSamlProvider</c>. They allow anonymous callers and are left out of the API description.
    /// </summary>
    public static IEndpointRouteBuilder MapJeffOpsSaml(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var group = endpoints.MapGroup(Prefix).AllowAnonymous().ExcludeFromDescription();
        group.MapGet("{provider}", Start);
        group.MapPost("{provider}/acs", AssertionConsumerAsync).DisableAntiforgery();
        group.MapGet("{provider}/metadata", Metadata);
        group.MapMethods("{provider}/slo", [HttpMethods.Get, HttpMethods.Post], SingleLogoutAsync).DisableAntiforgery();
        return endpoints;
    }

    private static async Task<IResult> Start(string provider, string? returnUrl, string? login_hint, HttpContext context, SamlServices saml)
    {
        if (!await saml.Providers.PrepareAsync(provider, context.RequestAborted).ConfigureAwait(false))
        {
            return TypedResults.NotFound();
        }

        if (!saml.Providers.HasTrustAnchors(provider))
        {
            return BackToLogin(LocalOrRoot(returnUrl), "provider_error");
        }

        var settings = saml.Providers.Settings(provider);
        var entityId = saml.Providers.ServiceProviderEntityId(provider, saml.TokenServer, Origin(context));
        var request = new Saml2AuthnRequest(saml.Providers.Configuration(provider, entityId))
        {
            AssertionConsumerServiceUrl = new Uri(Origin(context), $"{Prefix}/{provider}/acs"),
            NameIdPolicy = new NameIdPolicy { AllowCreate = true },
        };
        if (!string.IsNullOrWhiteSpace(login_hint))
        {
            request.Subject = new Subject { NameID = new NameID { ID = login_hint } };
        }

        // The client asked for a fresh sign-in: so does this server, of the provider.
        if (Application.Federation.FreshSignIn.RequiredAfter(LocalOrRoot(returnUrl), saml.Time.GetUtcNow()) is not null)
        {
            request.ForceAuthn = true;
        }

        // The request id binds the response to this browser: the cookie must come back with an answer to this request.
        var expires = saml.Time.GetUtcNow() + settings.SignInTimeout;
        var state = string.Create(CultureInfo.InvariantCulture, $"{request.IdAsString}|{expires.ToUnixTimeSeconds()}|{LocalOrRoot(returnUrl)}");
        context.Response.Cookies.Append(CookieName(provider), saml.Protector.Protect(state), new CookieOptions
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            // The response arrives as a cross-site POST from the provider: the cookie must travel with it.
            SameSite = SameSiteMode.None,
            Path = $"/{Prefix}/{provider}",
            Expires = expires,
            IsEssential = true,
        });

        var binding = new Saml2RedirectBinding();
        binding.Bind(request);
        return Results.Redirect(binding.RedirectLocation.OriginalString);
    }

    private static async Task<IResult> AssertionConsumerAsync(
        string provider,
        HttpContext context,
        SamlServices saml,
        ICommandHandler<CompleteExternalSignInCommand, ExternalSignInResult> completeSignIn,
        Application.Federation.IHomeRealmDirectory realms,
        ClaimNames names,
        ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger("JeffOps.Authentication.Federation.Saml");
        if (!context.Request.HasFormContentType || !await saml.Providers.PrepareAsync(provider, context.RequestAborted).ConfigureAwait(false))
        {
            return TypedResults.NotFound();
        }

        if (!saml.Providers.HasTrustAnchors(provider))
        {
            LogRejected(logger, provider, "no certificate to verify the provider's signature");
            return BackToLogin("/", "provider_error");
        }

        var (requestId, returnUrl) = ReadState(context, provider, saml);
        context.Response.Cookies.Delete(CookieName(provider), new CookieOptions { Path = $"/{Prefix}/{provider}", Secure = context.Request.IsHttps, SameSite = SameSiteMode.None });
        if (requestId is null)
        {
            LogRejected(logger, provider, "no pending sign-in for this browser");
            return BackToLogin("/", "signin_expired");
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
        var generic = new ITfoxtec.Identity.Saml2.Http.HttpRequest
        {
            Method = "POST",
            Form = new NameValueCollection(),
            Query = new NameValueCollection(),
        };
        foreach (var (key, value) in form)
        {
            generic.Form[key] = value.ToString();
        }

        var entityId = saml.Providers.ServiceProviderEntityId(provider, saml.TokenServer, Origin(context));
        var document = Parse(form["SAMLResponse"].ToString());
        if (document is null)
        {
            LogRejected(logger, provider, "response not readable");
            return BackToLogin(returnUrl, "provider_error");
        }

        if (saml.Providers.Settings(provider).RequireEncryptedAssertions && !IsEncrypted(document))
        {
            LogRejected(logger, provider, "assertion not encrypted");
            return BackToLogin(returnUrl, "provider_error");
        }

        // Before anything is decrypted: a weak scheme could make this endpoint a decryption oracle.
        if (RefusedEncryption(document, saml.Providers.Settings(provider).AllowCbcEncryption) is { } weak)
        {
            LogRejected(logger, provider, $"encrypted with {weak}");
            return BackToLogin(returnUrl, "provider_error");
        }

        var response = new Saml2AuthnResponse(saml.Providers.Configuration(provider, entityId));
        try
        {
            var binding = new Saml2PostBinding();
            binding.ReadSamlResponse(generic, response);
            if (response.Status != Saml2StatusCodes.Success)
            {
                LogRejected(logger, provider, $"status {response.Status}");
                return BackToLogin(returnUrl, "provider_error");
            }

            binding.Unbind(generic, response);
        }
#pragma warning disable CA1031 // Any failure to read or validate the response refuses the sign-in (fail closed).
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogInvalid(logger, provider, exception);
            return BackToLogin(returnUrl, "provider_error");
        }

        var acs = new Uri(Origin(context), $"{Prefix}/{provider}/acs");
        var rejection = string.Equals(response.InResponseTo?.Value, requestId, StringComparison.Ordinal)
            ? Rejection(response.Saml2SecurityToken?.Assertion, requestId, acs, saml.Providers.Settings(provider).IdpEntityId, saml.Time.GetUtcNow())
            : "response does not answer this browser's request";
        if (rejection is not null)
        {
            LogRejected(logger, provider, rejection);
            return BackToLogin(returnUrl, "provider_error");
        }

        // Once only, across every instance: a captured response can't be posted again.
        var assertion = response.Saml2SecurityToken!.Assertion;
        var validUntil = assertion.Conditions?.NotOnOrAfter is { } notOnOrAfter
            ? new DateTimeOffset(DateTime.SpecifyKind(notOnOrAfter, DateTimeKind.Utc))
            : saml.Time.GetUtcNow().AddHours(1);
        if (!await saml.Replay.TryAddAsync(ReplayKeys.For("saml", $"{assertion.Issuer.Value}|{assertion.Id.Value}"), validUntil, context.RequestAborted).ConfigureAwait(false))
        {
            LogRejected(logger, provider, "assertion seen before");
            return BackToLogin(returnUrl, "provider_error");
        }

        // The subject and authentication context come from the signed assertion; attributes may not pose as them.
        var claims = new ClaimsIdentity(response.ClaimsIdentity.Claims.Where(claim => !ReservedClaimTypes.Contains(claim.Type)), "saml");
        claims.AddClaim(new Claim(Saml2ClaimTypes.NameId, assertion.Subject.NameId.Value));
        if (assertion.Subject.NameId.Format is { } format)
        {
            claims.AddClaim(new Claim(Saml2ClaimTypes.NameIdFormat, format.OriginalString));
        }

        if (AuthnContextOf(response) is { } authnContext)
        {
            claims.AddClaim(new Claim(SamlProviders.AuthnContextClaim, authnContext));
        }

        // A fresh sign-in was asked for (ForceAuthn): the provider's own single sign-on session, from before, doesn't count.
        var authenticatedAt = assertion.Statements.OfType<Saml2AuthenticationStatement>().FirstOrDefault()?.AuthenticationInstant is { } instant
            ? new DateTimeOffset(DateTime.SpecifyKind(instant, DateTimeKind.Utc))
            : (DateTimeOffset?)null;
        if (!Application.Federation.FreshSignIn.ProviderAuthenticatedInTime(authenticatedAt, Application.Federation.FreshSignIn.RequiredAfter(returnUrl, saml.Time.GetUtcNow())))
        {
            LogRejected(logger, provider, "authenticated before the fresh sign-in the client asked for");
            return BackToLogin(returnUrl, Application.Federation.FreshSignIn.ReauthenticationRequired);
        }

        var identity = saml.Providers.Map(provider, new ClaimsPrincipal(claims));
        if (identity.IsFailure)
        {
            return BackToLogin(returnUrl, identity.Error.Code);
        }

        // A tenant's own provider signs in only that tenant's people: addresses in the domains the tenant verified.
        if (saml.Providers.Settings(provider).OwnerTenantId is { } owner
            && (Application.Federation.HomeRealm.DomainOf(identity.Value.Email) is not { } domain
                || await realms.FindByDomainAsync(domain, context.RequestAborted).ConfigureAwait(false) is not { } realm
                || realm.TenantId != owner))
        {
            LogRejected(logger, provider, "address outside the tenant's verified domains");
            return BackToLogin(returnUrl, "domain_not_allowed");
        }

        var signedIn = await completeSignIn.HandleAsync(new CompleteExternalSignInCommand(identity.Value), context.RequestAborted).ConfigureAwait(false);
        if (signedIn.IsFailure)
        {
            return BackToLogin(returnUrl, signedIn.Error.Code);
        }

        var scheme = saml.TokenServer.Value.SignInScheme;
        // Remember where the session came from, so signing out here can sign out at the provider too (single logout).
        var principal = SignInPrincipal.Create(signedIn.Value.AccountId, signedIn.Value.Strength, saml.Time.GetUtcNow(), names, scheme, provider);
        var session = (ClaimsIdentity)principal.Identity!;
        session.AddClaim(new Claim(SamlSignOut.ProviderClaim, provider));
        session.AddClaim(new Claim(SamlSignOut.NameIdClaim, assertion.Subject.NameId.Value));
        if (assertion.Subject.NameId.Format is { } nameIdFormat)
        {
            session.AddClaim(new Claim(SamlSignOut.NameIdFormatClaim, nameIdFormat.OriginalString));
        }

        if (assertion.Statements.OfType<Saml2AuthenticationStatement>().FirstOrDefault()?.SessionIndex is { Length: > 0 } sessionIndex)
        {
            session.AddClaim(new Claim(SamlSignOut.SessionIndexClaim, sessionIndex));
        }

        await context.SignInAsync(scheme, principal).ConfigureAwait(false);
        return Results.Redirect(returnUrl);
    }

    /// <summary>
    /// Single logout started by the identity provider: a signed LogoutRequest names the user (NameID); every session of the
    /// linked account ends here (tokens revoked, clients told through back-channel logout), and the provider gets a
    /// LogoutResponse. Unsigned or otherwise invalid requests are refused.
    /// </summary>
    private static async Task<IResult> SingleLogoutAsync(
        string provider,
        HttpContext context,
        SamlServices saml,
        Application.Abstractions.IAccountRepository accounts,
        Application.Abstractions.IUnitOfWork unitOfWork,
        Abstractions.Auditing.IAuditSink audit,
        ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger("JeffOps.Authentication.Federation.Saml");
        if (!await saml.Providers.PrepareAsync(provider, context.RequestAborted).ConfigureAwait(false))
        {
            return TypedResults.NotFound();
        }

        // Without a certificate the binding would accept an unsigned request: refuse instead.
        if (!saml.Providers.HasTrustAnchors(provider))
        {
            LogRejected(logger, provider, "no certificate to verify the provider's signature");
            return TypedResults.BadRequest();
        }

        var settings = saml.Providers.Settings(provider);
        var entityId = saml.Providers.ServiceProviderEntityId(provider, saml.TokenServer, Origin(context));
        var configuration = saml.Providers.Configuration(provider, entityId);
        var generic = await GenericRequestAsync(context).ConfigureAwait(false);
        Saml2Binding binding = HttpMethods.IsGet(context.Request.Method) ? new Saml2RedirectBinding() : new Saml2PostBinding();

        if (!string.IsNullOrEmpty(generic.Query["SAMLResponse"]) || !string.IsNullOrEmpty(generic.Form["SAMLResponse"]))
        {
            return LogoutResponse(provider, generic, binding, configuration, saml, logger);
        }

        // Only signed requests: anyone could otherwise sign a user out. The redirect binding signs the query string.
        var signed = HttpMethods.IsGet(context.Request.Method)
            ? !string.IsNullOrEmpty(generic.Query["Signature"])
            : (generic.Form["SAMLRequest"] is { } posted && DecodedContainsSignature(posted));
        var request = new Saml2LogoutRequest(configuration);
        try
        {
            if (!signed || !binding.IsRequest(generic))
            {
                throw new InvalidOperationException("Not a signed logout request.");
            }

            binding.Unbind(generic, request);
            if (LogoutRejection(request, new Uri(Origin(context), $"{Prefix}/{provider}/slo"), saml) is { } reason)
            {
                throw new InvalidOperationException(reason);
            }

            // Each logout request counts once, across every instance.
            if (!await saml.Replay.TryAddAsync(
                    ReplayKeys.For("saml-logout", request.XmlDocument.DocumentElement!.GetAttribute("ID")), saml.Time.GetUtcNow() + TimeSpan.FromMinutes(10), context.RequestAborted)
                .ConfigureAwait(false))
            {
                throw new InvalidOperationException("logout request replayed");
            }
        }
#pragma warning disable CA1031 // Any failure to read or validate the request refuses it (fail closed).
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogInvalid(logger, provider, exception);
            return TypedResults.BadRequest();
        }

        if (request.NameId?.Value is { Length: > 0 } nameId
            && await accounts.FindByExternalLoginAsync(new Domain.Accounts.ExternalLoginKey(settings.LoginIssuer ?? settings.IdpEntityId!, nameId), context.RequestAborted).ConfigureAwait(false) is { } account)
        {
            var now = saml.Time.GetUtcNow();
            account.RevokeSessions(now, "saml_single_logout");
            await unitOfWork.SaveChangesAsync(context.RequestAborted).ConfigureAwait(false);
            await audit.WriteAsync(new Abstractions.Auditing.AuditRecord("saml.single_logout", "account", account.Id.ToString())
            {
                OccurredAt = now,
                Details = new Dictionary<string, string?> { ["provider"] = provider },
            }, context.RequestAborted).ConfigureAwait(false);
        }

        if (saml.Providers.SingleLogoutUrl(provider) is not { } logoutUrl)
        {
            return Results.Content("You are signed out.", "text/plain");
        }

        var response = new Saml2LogoutResponse(configuration)
        {
            InResponseTo = request.Id,
            Status = Saml2StatusCodes.Success,
            Destination = logoutUrl,
        };
        // RelayState is covered by the signature only in the redirect binding; a posted one isn't passed on.
        var reply = new Saml2RedirectBinding { RelayState = binding is Saml2RedirectBinding ? binding.RelayState : null };
        reply.Bind(response);
        return Results.Redirect(reply.RedirectLocation.OriginalString);
    }

    /// <summary>
    /// Why a signed LogoutRequest is not for here and now, or null: it must name this endpoint (<c>Destination</c>), be recent
    /// (<c>IssueInstant</c> within five minutes, <c>NotOnOrAfter</c> not passed) and carry an ID (checked for replay after).
    /// </summary>
    private static string? LogoutRejection(Saml2LogoutRequest request, Uri slo, SamlServices saml)
    {
        var root = request.XmlDocument?.DocumentElement;
        var now = saml.Time.GetUtcNow();
        var skew = TimeSpan.FromMinutes(5);
        if (root is null || !string.Equals(root.GetAttribute("Destination"), slo.AbsoluteUri, StringComparison.Ordinal))
        {
            return "logout request for another endpoint";
        }

        if (!DateTimeOffset.TryParse(root.GetAttribute("IssueInstant"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var issued)
            || issued > now + skew || issued < now - skew)
        {
            return "logout request too old or from the future";
        }

        if (root.GetAttribute("NotOnOrAfter") is { Length: > 0 } notOnOrAfter
            && (!DateTimeOffset.TryParse(notOnOrAfter, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var expires) || expires <= now))
        {
            return "logout request expired";
        }

        return string.IsNullOrEmpty(root.GetAttribute("ID")) ? "logout request without an ID" : null;
    }

    /// <summary>
    /// The provider's answer to a logout this server started: the user is already signed out here, so whatever it says, the
    /// browser goes back to finish the end-session request — but only to the local path the RelayState protects, and only
    /// for an answer to that request.
    /// </summary>
    private static IResult LogoutResponse(
        string provider, ITfoxtec.Identity.Saml2.Http.HttpRequest generic, Saml2Binding binding, Saml2Configuration configuration, SamlServices saml, ILogger logger)
    {
        var relay = generic.Query["RelayState"] ?? generic.Form["RelayState"];
        if (SamlSignOut.ReadRelayState(relay, saml) is not { } state)
        {
            LogRejected(logger, provider, "logout response without a valid relay state");
            return Results.Redirect("/");
        }

        var response = new Saml2LogoutResponse(configuration);
        try
        {
            binding.Unbind(generic, response);
            if (!string.Equals(response.InResponseTo?.Value, state.RequestId, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("logout response to another request");
            }

            if (response.Status != Saml2StatusCodes.Success)
            {
                LogRejected(logger, provider, $"logout status {response.Status}");
            }
        }
#pragma warning disable CA1031 // The user is signed out here regardless; an invalid answer is only logged.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogInvalid(logger, provider, exception);
        }

        return Results.Redirect(state.ReturnUrl);
    }

    private static async Task<ITfoxtec.Identity.Saml2.Http.HttpRequest> GenericRequestAsync(HttpContext context)
    {
        var generic = new ITfoxtec.Identity.Saml2.Http.HttpRequest
        {
            Method = context.Request.Method,
            QueryString = context.Request.QueryString.Value ?? string.Empty,
            Query = new NameValueCollection(),
            Form = new NameValueCollection(),
        };
        foreach (var (key, value) in context.Request.Query)
        {
            generic.Query[key] = value.ToString();
        }

        if (context.Request.HasFormContentType)
        {
            foreach (var (key, value) in await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false))
            {
                generic.Form[key] = value.ToString();
            }
        }

        return generic;
    }

    private static bool DecodedContainsSignature(string posted)
    {
        try
        {
            return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(posted)).Contains("Signature", StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static async Task<IResult> Metadata(string provider, HttpContext context, SamlServices saml)
    {
        // This server's own metadata: the provider's isn't needed (nor downloaded) for it.
        if (!await saml.Providers.PrepareAsync(provider, context.RequestAborted, withMetadata: false).ConfigureAwait(false))
        {
            return TypedResults.NotFound();
        }

        var entityId = saml.Providers.ServiceProviderEntityId(provider, saml.TokenServer, Origin(context));
        var acs = new Uri(Origin(context), $"{Prefix}/{provider}/acs").AbsoluteUri;
        var slo = new Uri(Origin(context), $"{Prefix}/{provider}/slo").AbsoluteUri;
        var signing = saml.Providers.SigningCertificate(provider);
        var decryption = saml.Providers.DecryptionCertificate(provider);
        var keyDescriptor = KeyDescriptor("signing", signing) + KeyDescriptor("encryption", decryption);
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{System.Security.SecurityElement.Escape(entityId)}">
              <md:SPSSODescriptor AuthnRequestsSigned="{(signing is null ? "false" : "true")}" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{keyDescriptor}
                <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{System.Security.SecurityElement.Escape(slo)}"/>
                <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
                <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{System.Security.SecurityElement.Escape(acs)}" index="0" isDefault="true"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>
            """;
        return Results.Content(xml, "application/samlmetadata+xml");
    }

    private static string KeyDescriptor(string use, System.Security.Cryptography.X509Certificates.X509Certificate2? certificate) =>
        certificate is null ? string.Empty : $"""

                <md:KeyDescriptor use="{use}">
                  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{Convert.ToBase64String(certificate.RawData)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
                </md:KeyDescriptor>
            """;

    private static (string? RequestId, string ReturnUrl) ReadState(HttpContext context, string provider, SamlServices saml)
    {
        if (!context.Request.Cookies.TryGetValue(CookieName(provider), out var value) || string.IsNullOrEmpty(value))
        {
            return (null, "/");
        }

        try
        {
            var parts = saml.Protector.Unprotect(value).Split('|', 3);
            if (parts.Length == 3 && long.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var expires)
                && DateTimeOffset.FromUnixTimeSeconds(expires) > saml.Time.GetUtcNow())
            {
                return (parts[0], LocalOrRoot(parts[2]));
            }
        }
        catch (CryptographicException)
        {
            // Tampered with or from an old key ring: no pending sign-in.
        }

        return (null, "/");
    }

    private static readonly HashSet<string> ReservedClaimTypes =
        [Saml2ClaimTypes.NameId, Saml2ClaimTypes.NameIdFormat, Saml2ClaimTypes.SessionIndex, ClaimTypes.NameIdentifier, SamlProviders.AuthnContextClaim];

    private const string Bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    private const string Transient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

    /// <summary>
    /// Why the signed assertion does not answer this browser's request, or null when it does. The Response element around it
    /// may be unsigned (only the assertion is, by default, at ADFS and Entra), so the binding to the request is checked on
    /// the assertion: its issuer, and a bearer confirmation naming this request (<c>InResponseTo</c>) and this endpoint
    /// (<c>Recipient</c>) that has not expired. Transient NameIDs are refused: they can't identify anyone twice.
    /// </summary>
    private static string? Rejection(Saml2Assertion? assertion, string requestId, Uri acs, string? idpEntityId, DateTimeOffset now)
    {
        if (assertion?.Subject?.NameId is not { } nameId || string.IsNullOrEmpty(nameId.Value))
        {
            return "no subject";
        }

        if (!string.Equals(assertion.Issuer?.Value, idpEntityId, StringComparison.Ordinal))
        {
            return "assertion from another issuer";
        }

        if (string.Equals(nameId.Format?.OriginalString, Transient, StringComparison.Ordinal))
        {
            return "transient NameID";
        }

        var confirmed = assertion.Subject.SubjectConfirmations.Any(confirmation =>
            string.Equals(confirmation.Method?.OriginalString, Bearer, StringComparison.Ordinal)
            && confirmation.SubjectConfirmationData is { } data
            && string.Equals(data.InResponseTo?.Value, requestId, StringComparison.Ordinal)
            && string.Equals(data.Recipient?.AbsoluteUri, acs.AbsoluteUri, StringComparison.Ordinal)
            && data.NotOnOrAfter is { } notOnOrAfter
            && new DateTimeOffset(DateTime.SpecifyKind(notOnOrAfter, DateTimeKind.Utc)) > now);
        return confirmed ? null : "no bearer confirmation for this request and endpoint";
    }

    /// <summary>The response's XML (no DTDs, no external resources), or null when it isn't base64 XML.</summary>
    private static System.Xml.XmlDocument? Parse(string samlResponse)
    {
        try
        {
            var document = new System.Xml.XmlDocument { XmlResolver = null };
            using var reader = System.Xml.XmlReader.Create(
                new MemoryStream(Convert.FromBase64String(samlResponse)),
                new System.Xml.XmlReaderSettings { DtdProcessing = System.Xml.DtdProcessing.Prohibit, XmlResolver = null });
            document.Load(reader);
            return document;
        }
        catch (Exception exception) when (exception is FormatException or System.Xml.XmlException)
        {
            return null;
        }
    }

    /// <summary>Whether the posted response carries its assertion encrypted, and no plain one beside it.</summary>
    private static bool IsEncrypted(System.Xml.XmlDocument document)
    {
        const string Assertion = "urn:oasis:names:tc:SAML:2.0:assertion";
        return document.GetElementsByTagName("EncryptedAssertion", Assertion).Count == 1
            && document.GetElementsByTagName("Assertion", Assertion).Count == 0;
    }

    private const string XmlEnc = "http://www.w3.org/2001/04/xmlenc#";

    /// <summary>Key transport this server accepts: RSA-OAEP only.</summary>
    private static readonly string[] KeyTransportAlgorithms = [XmlEnc + "rsa-oaep-mgf1p", "http://www.w3.org/2009/xmlenc11#rsa-oaep"];

    private static readonly string[] GcmAlgorithms =
        ["http://www.w3.org/2009/xmlenc11#aes128-gcm", "http://www.w3.org/2009/xmlenc11#aes192-gcm", "http://www.w3.org/2009/xmlenc11#aes256-gcm"];

    private static readonly string[] CbcAlgorithms = [XmlEnc + "aes128-cbc", XmlEnc + "aes192-cbc", XmlEnc + "aes256-cbc"];

    /// <summary>
    /// What the response is encrypted with that this server refuses (a fixed name, never the response's own text), or null.
    /// Keys must travel with RSA-OAEP (never PKCS#1 v1.5, open to padding-oracle attacks); data must be AES-GCM, or AES-CBC
    /// where <paramref name="allowCbc"/>.
    /// </summary>
    private static string? RefusedEncryption(System.Xml.XmlDocument document, bool allowCbc)
    {
        foreach (var method in document.GetElementsByTagName("EncryptionMethod", XmlEnc).OfType<System.Xml.XmlElement>())
        {
            var algorithm = method.GetAttribute("Algorithm");
            var allowed = method.ParentNode is System.Xml.XmlElement { LocalName: "EncryptedKey", NamespaceURI: XmlEnc }
                ? KeyTransportAlgorithms.Contains(algorithm, StringComparer.Ordinal)
                : GcmAlgorithms.Contains(algorithm, StringComparer.Ordinal) || (allowCbc && CbcAlgorithms.Contains(algorithm, StringComparer.Ordinal));
            if (!allowed)
            {
                return algorithm switch
                {
                    XmlEnc + "rsa-1_5" => "RSA PKCS#1 v1.5",
                    _ when CbcAlgorithms.Contains(algorithm, StringComparer.Ordinal) => "AES-CBC",
                    _ => "an unsupported algorithm",
                };
            }
        }

        return null;
    }

    private static string? AuthnContextOf(Saml2AuthnResponse response) =>
        response.Saml2SecurityToken?.Assertion.Statements.OfType<Saml2AuthenticationStatement>().FirstOrDefault()?.AuthenticationContext?.ClassReference?.OriginalString;

    private static string CookieName(string provider) => "jeffops-saml-" + provider;

    private static Uri Origin(HttpContext context) => new($"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/");

    private static IResult BackToLogin(string returnUrl, string error) =>
        Results.Redirect($"{LoginPath}?returnUrl={Uri.EscapeDataString(returnUrl)}&error={Uri.EscapeDataString(error)}");

    private static string LocalOrRoot(string? returnUrl) =>
        Abstractions.Http.LocalRedirect.OrRoot(returnUrl);

    [LoggerMessage(EventId = 8501, Level = LogLevel.Warning, Message = "Rejected a SAML response from {Provider}: {Reason}")]
    private static partial void LogRejected(ILogger logger, string provider, string reason);

    [LoggerMessage(EventId = 8502, Level = LogLevel.Warning, Message = "An invalid SAML response from {Provider} was rejected.")]
    private static partial void LogInvalid(ILogger logger, string provider, Exception exception);
}

/// <summary>What the SAML endpoints need, in one injectable bundle.</summary>
internal sealed class SamlServices(
    SamlProviders providers,
    IOptionsMonitor<SamlProviderOptions> options,
    IOptions<TokenServerOptions> tokenServer,
    IReplayCache replay,
    IDataProtectionProvider dataProtection,
    TimeProvider time)
{
    public SamlProviders Providers { get; } = providers;

    public IOptionsMonitor<SamlProviderOptions> Options { get; } = options;

    public IOptions<TokenServerOptions> TokenServer { get; } = tokenServer;

    public IReplayCache Replay { get; } = replay;

    public IDataProtector Protector { get; } = dataProtection.CreateProtector("JeffOps.Federation.Saml.Request");

    public TimeProvider Time { get; } = time;
}

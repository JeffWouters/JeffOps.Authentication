using System.Collections.Specialized;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.Schemas;
using JeffOps.Authentication.Abstractions.Claims;
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
using Microsoft.IdentityModel.Tokens;
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
        return endpoints;
    }

    private static IResult Start(string provider, string? returnUrl, string? login_hint, HttpContext context, SamlServices saml)
    {
        if (!saml.Providers.Handles(provider))
        {
            return TypedResults.NotFound();
        }

        var settings = saml.Options.Get(provider);
        var entityId = saml.Providers.ServiceProviderEntityId(provider, saml.TokenServer, Origin(context));
        var request = new Saml2AuthnRequest(saml.Providers.Configuration(provider, entityId, saml.ReplayCache))
        {
            AssertionConsumerServiceUrl = new Uri(Origin(context), $"{Prefix}/{provider}/acs"),
            NameIdPolicy = new NameIdPolicy { AllowCreate = true },
        };
        if (!string.IsNullOrWhiteSpace(login_hint))
        {
            request.Subject = new Subject { NameID = new NameID { ID = login_hint } };
        }

        // The request id binds the response to this browser: the cookie must come back with an answer to this request.
        var expires = saml.Time.GetUtcNow() + settings.SignInTimeout;
        var state = string.Create(CultureInfo.InvariantCulture, $"{request.IdAsString}|{LocalOrRoot(returnUrl)}|{expires.ToUnixTimeSeconds()}");
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
        ClaimNames names,
        ILoggerFactory loggers)
    {
        var logger = loggers.CreateLogger("JeffOps.Authentication.Federation.Saml");
        if (!saml.Providers.Handles(provider) || !context.Request.HasFormContentType)
        {
            return TypedResults.NotFound();
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
        var response = new Saml2AuthnResponse(saml.Providers.Configuration(provider, entityId, saml.ReplayCache));
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

        if (!string.Equals(response.InResponseToAsString, requestId, StringComparison.Ordinal))
        {
            LogRejected(logger, provider, "response does not answer this browser's request");
            return BackToLogin(returnUrl, "provider_error");
        }

        var claims = new ClaimsIdentity(response.ClaimsIdentity.Claims, "saml");
        if (AuthnContextOf(response) is { } authnContext)
        {
            claims.AddClaim(new Claim(SamlProviders.AuthnContextClaim, authnContext));
        }

        var identity = saml.Providers.Map(provider, new ClaimsPrincipal(claims));
        if (identity.IsFailure)
        {
            return BackToLogin(returnUrl, identity.Error.Code);
        }

        var signedIn = await completeSignIn.HandleAsync(new CompleteExternalSignInCommand(identity.Value), context.RequestAborted).ConfigureAwait(false);
        if (signedIn.IsFailure)
        {
            return BackToLogin(returnUrl, signedIn.Error.Code);
        }

        var scheme = saml.TokenServer.Value.SignInScheme;
        await context.SignInAsync(scheme, SignInPrincipal.Create(signedIn.Value.AccountId, signedIn.Value.Strength, saml.Time.GetUtcNow(), names, scheme)).ConfigureAwait(false);
        return Results.Redirect(returnUrl);
    }

    private static IResult Metadata(string provider, HttpContext context, SamlServices saml)
    {
        if (!saml.Providers.Handles(provider))
        {
            return TypedResults.NotFound();
        }

        var entityId = saml.Providers.ServiceProviderEntityId(provider, saml.TokenServer, Origin(context));
        var acs = new Uri(Origin(context), $"{Prefix}/{provider}/acs").AbsoluteUri;
        var xml = $"""
            <?xml version="1.0" encoding="UTF-8"?>
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{System.Security.SecurityElement.Escape(entityId)}">
              <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
                <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{System.Security.SecurityElement.Escape(acs)}" index="0" isDefault="true"/>
              </md:SPSSODescriptor>
            </md:EntityDescriptor>
            """;
        return Results.Content(xml, "application/samlmetadata+xml");
    }

    private static (string? RequestId, string ReturnUrl) ReadState(HttpContext context, string provider, SamlServices saml)
    {
        if (!context.Request.Cookies.TryGetValue(CookieName(provider), out var value) || string.IsNullOrEmpty(value))
        {
            return (null, "/");
        }

        try
        {
            var parts = saml.Protector.Unprotect(value).Split('|');
            if (parts.Length == 3 && long.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var expires)
                && DateTimeOffset.FromUnixTimeSeconds(expires) > saml.Time.GetUtcNow())
            {
                return (parts[0], LocalOrRoot(parts[1]));
            }
        }
        catch (CryptographicException)
        {
            // Tampered with or from an old key ring: no pending sign-in.
        }

        return (null, "/");
    }

    private static string? AuthnContextOf(Saml2AuthnResponse response) =>
        response.Saml2SecurityToken?.Assertion.Statements.OfType<Saml2AuthenticationStatement>().FirstOrDefault()?.AuthenticationContext?.ClassReference?.OriginalString;

    private static string CookieName(string provider) => "jeffops-saml-" + provider;

    private static Uri Origin(HttpContext context) => new($"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/");

    private static IResult BackToLogin(string returnUrl, string error) =>
        Results.Redirect($"{LoginPath}?returnUrl={Uri.EscapeDataString(returnUrl)}&error={Uri.EscapeDataString(error)}");

    private static string LocalOrRoot(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//", StringComparison.Ordinal) && !returnUrl.StartsWith("/\\", StringComparison.Ordinal)
            ? returnUrl
            : "/";

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
    ITokenReplayCache replayCache,
    IDataProtectionProvider dataProtection,
    TimeProvider time)
{
    public SamlProviders Providers { get; } = providers;

    public IOptionsMonitor<SamlProviderOptions> Options { get; } = options;

    public IOptions<TokenServerOptions> TokenServer { get; } = tokenServer;

    public ITokenReplayCache ReplayCache { get; } = replayCache;

    public IDataProtector Protector { get; } = dataProtection.CreateProtector("JeffOps.Federation.Saml.Request");

    public TimeProvider Time { get; } = time;
}

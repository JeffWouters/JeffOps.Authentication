using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Application.Features.Federation.CompleteExternalSignIn;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.SharedKernel.Handlers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Endpoints.Features.Federation;

/// <summary>
/// Signing in through external providers (docs/DESIGN.md §8): home realm discovery, the challenge that sends the user to the
/// provider, and the callback that links the account and signs it into the sign-in scheme.
/// </summary>
internal static class FederationEndpoints
{
    public const string LoginPath = "/account/login";

    public static void Map(IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup(string.Empty).AllowAnonymous().ExcludeFromDescription();

        group.MapGet("account/login/discover", Discover);
        group.MapGet("signin/{provider}", Challenge);
        group.MapMethods("signin/callback/{provider}", [HttpMethods.Get, HttpMethods.Post], CallbackAsync);
    }

    /// <summary>Sends the user to the provider for their email domain, or back to the login page to choose one.</summary>
    private static async Task<IResult> Discover(
        string? email,
        string? returnUrl,
        string? idp,
        IEnumerable<IExternalIdentityMapper> mappers,
        IHomeRealmDirectory realms,
        IOptions<FederationOptions> options,
        IOptions<TokenServerOptions> tokenServer,
        HttpContext context)
    {
        var local = LocalOrRoot(returnUrl);
        var client = ClientProviders.ForReturnUrl(tokenServer.Value, local);
        var known = mappers.SelectMany(mapper => mapper.Providers).Select(provider => provider.Name)
            .Where(provider => ClientProviders.Allows(client, provider)).ToList();

        return await HomeRealm.DiscoverAsync(email, idp, options.Value, known, realms, context.RequestAborted).ConfigureAwait(false) is { } provider
            ? Results.Redirect($"/signin/{Uri.EscapeDataString(provider)}?returnUrl={Uri.EscapeDataString(local)}&login_hint={Uri.EscapeDataString(email ?? string.Empty)}")
            : Results.Redirect($"{LoginPath}?returnUrl={Uri.EscapeDataString(local)}&email={Uri.EscapeDataString(email ?? string.Empty)}");
    }

    private static IResult Challenge(
        string provider,
        string? returnUrl,
        string? login_hint,
        IEnumerable<IExternalIdentityMapper> mappers,
        IEnumerable<IExternalProviderChallenge> challenges,
        IOptions<TokenServerOptions> tokenServer)
    {
        // Providers tenants registered aren't listed; their own sign-in endpoint checks they exist and may still be used.
        if (!mappers.SelectMany(mapper => mapper.Providers).Any(known => string.Equals(known.Name, provider, StringComparison.Ordinal))
            && !(TenantProviderNames.IsTenantProvider(provider) && challenges.Any(challenge => challenge.Handles(provider))))
        {
            return TypedResults.NotFound();
        }

        // Not one of the client's providers: the authorize endpoint would refuse the sign-in anyway, so don't send the user there.
        if (!ClientProviders.Allows(ClientProviders.ForReturnUrl(tokenServer.Value, LocalOrRoot(returnUrl)), provider))
        {
            return BackToLogin(LocalOrRoot(returnUrl), "provider_not_allowed");
        }

        if (challenges.FirstOrDefault(challenge => challenge.Handles(provider)) is { } other)
        {
            return Results.Redirect(other.ChallengePath(provider, LocalOrRoot(returnUrl), login_hint));
        }

        var properties = new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictClientAspNetCoreConstants.Properties.ProviderName] = provider,
        })
        {
            RedirectUri = LocalOrRoot(returnUrl),
        };

        if (!string.IsNullOrWhiteSpace(login_hint))
        {
            properties.Items[OpenIddictClientAspNetCoreConstants.Properties.LoginHint] = login_hint;
        }

        return Results.Challenge(properties, [OpenIddictClientAspNetCoreDefaults.AuthenticationScheme]);
    }

    private static async Task<IResult> CallbackAsync(
        HttpContext context,
        IEnumerable<IExternalIdentityMapper> mappers,
        ICommandHandler<CompleteExternalSignInCommand, ExternalSignInResult> completeSignIn,
        ClaimNames names,
        IOptions<TokenServerOptions> options,
        TimeProvider time)
    {
        var result = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme).ConfigureAwait(false);
        var returnUrl = LocalOrRoot(result.Properties?.RedirectUri);

        if (result.Principal is not { } principal || principal.GetClaim(Claims.Private.ProviderName) is not { } provider)
        {
            return BackToLogin(returnUrl, "provider_error");
        }

        var mapper = mappers.FirstOrDefault(candidate => candidate.Providers.Any(known => string.Equals(known.Name, provider, StringComparison.Ordinal)));
        if (mapper is null)
        {
            return BackToLogin(returnUrl, "provider_unknown");
        }

        var identity = mapper.Map(provider, principal);
        if (identity.IsFailure)
        {
            return BackToLogin(returnUrl, identity.Error.Code);
        }

        var signedIn = await completeSignIn.HandleAsync(new CompleteExternalSignInCommand(identity.Value), context.RequestAborted).ConfigureAwait(false);
        if (signedIn.IsFailure)
        {
            return BackToLogin(returnUrl, signedIn.Error.Code);
        }

        var signInScheme = options.Value.SignInScheme;
        await context.SignInAsync(
            signInScheme,
            SignInPrincipal.Create(signedIn.Value.AccountId, signedIn.Value.Strength, time.GetUtcNow(), names, signInScheme, provider)).ConfigureAwait(false);

        return Results.Redirect(returnUrl);
    }

    /// <summary>Only local paths: a return URL pointing elsewhere would make sign-in an open redirect.</summary>
    internal static string LocalOrRoot(string? returnUrl) =>
        Abstractions.Http.LocalRedirect.OrRoot(returnUrl);

    private static IResult BackToLogin(string returnUrl, string error) =>
        Results.Redirect($"{LoginPath}?returnUrl={Uri.EscapeDataString(returnUrl)}&error={Uri.EscapeDataString(error)}");
}

using System.Globalization;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.LocalAccounts.Application;
using JeffOps.Authentication.LocalAccounts.Application.Features.Authenticator;
using JeffOps.Authentication.LocalAccounts.Application.Features.Passkeys;
using JeffOps.Authentication.LocalAccounts.Application.Features.Passwords;
using JeffOps.Authentication.LocalAccounts.Application.Features.Registration;
using JeffOps.Authentication.LocalAccounts.Application.Features.SignIn;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Validation.AspNetCore;

namespace JeffOps.Authentication.LocalAccounts.Endpoints;

public sealed record RegisterRequest(string Email, string Password, string? DisplayName = null);

public sealed record TokenRequest(string Token);

public sealed record EmailRequest(string Email);

public sealed record ResetPasswordRequest(string Token, string NewPassword);

public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);

public sealed record CodeRequest(string Code);

public sealed record PasswordRequest(string Password);

public sealed record PasskeyRequest(JsonElement Credential, string? Name = null, string? ReturnUrl = null);

public static class LocalAccountEndpointRouteBuilderExtensions
{
    public const string Routes = "account/local";
    public const string LoginPage = "/account/login";
    public const string CodePage = "/account/login/code";

    private const string SecondFactorCookie = "jeffops-2fa";
    private const string PasskeyStateCookie = "jeffops-passkey";

    /// <summary>
    /// Maps local accounts under <c>account/local</c> (all answer 404 while local accounts are off):
    /// <list type="bullet">
    /// <item>Hosted-UI forms: <c>login</c> (email + password) and <c>login/code</c> (authenticator or recovery code).</item>
    /// <item>Public JSON: <c>register</c>, <c>verify-email</c>, <c>verify-email/resend</c>, <c>password/forgot</c>,
    /// <c>password/reset</c>, <c>passkey/login/options</c>, <c>passkey/login</c>.</item>
    /// <item>For the signed-in user (access token, own session only): <c>manage/password</c>, <c>manage/authenticator/*</c>,
    /// <c>manage/passkeys/*</c>.</item>
    /// </list>
    /// </summary>
    public static IEndpointRouteBuilder MapJeffOpsLocalAccounts(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var root = endpoints.MapGroup(Routes).WithTags("Local accounts").AddEndpointFilter<EnabledFilter>();

        var open = root.MapGroup(string.Empty).AllowAnonymous();
        open.MapPost("login", LoginAsync).DisableAntiforgery().ExcludeFromDescription();
        open.MapPost("login/code", CodeAsync).DisableAntiforgery().ExcludeFromDescription();
        open.MapPost("register", async (RegisterRequest request, ICommandHandler<RegisterLocalAccountCommand> handler, HttpContext context) =>
            Accepted(await handler.HandleAsync(new RegisterLocalAccountCommand(request.Email, request.Password, request.DisplayName), context.RequestAborted).ConfigureAwait(false)));
        open.MapPost("verify-email", async (TokenRequest request, ICommandHandler<VerifyEmailCommand> handler, HttpContext context) =>
            NoContent(await handler.HandleAsync(new VerifyEmailCommand(request.Token), context.RequestAborted).ConfigureAwait(false)));
        open.MapPost("verify-email/resend", async (EmailRequest request, ICommandHandler<ResendVerificationCommand> handler, HttpContext context) =>
            Accepted(await handler.HandleAsync(new ResendVerificationCommand(request.Email), context.RequestAborted).ConfigureAwait(false)));
        open.MapPost("password/forgot", async (EmailRequest request, ICommandHandler<RequestPasswordResetCommand> handler, HttpContext context) =>
            Accepted(await handler.HandleAsync(new RequestPasswordResetCommand(request.Email), context.RequestAborted).ConfigureAwait(false)));
        open.MapPost("password/reset", async (ResetPasswordRequest request, ICommandHandler<ResetPasswordCommand> handler, HttpContext context) =>
            NoContent(await handler.HandleAsync(new ResetPasswordCommand(request.Token, request.NewPassword), context.RequestAborted).ConfigureAwait(false)));
        open.MapPost("passkey/login/options", PasskeyLoginOptionsAsync);
        open.MapPost("passkey/login", PasskeyLoginAsync);

        var tokenPolicy = new AuthorizationPolicyBuilder(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme).RequireAuthenticatedUser().Build();
        var manage = root.MapGroup("manage").RequireAuthorization(tokenPolicy).AddEndpointFilter<OwnSessionFilter>();
        manage.MapPost("password", async (ChangePasswordRequest request, ICommandHandler<ChangePasswordCommand> handler, HttpContext context) =>
            NoContent(await handler.HandleAsync(new ChangePasswordCommand(AccountOf(context), request.CurrentPassword, request.NewPassword), context.RequestAborted).ConfigureAwait(false)));
        manage.MapPost("authenticator", async (ICommandHandler<BeginAuthenticatorCommand, AuthenticatorSetup> handler, HttpContext context) =>
            Ok(await handler.HandleAsync(new BeginAuthenticatorCommand(AccountOf(context)), context.RequestAborted).ConfigureAwait(false)));
        manage.MapPost("authenticator/confirm", async (CodeRequest request, ICommandHandler<ConfirmAuthenticatorCommand, IReadOnlyList<string>> handler, HttpContext context) =>
            Ok(await handler.HandleAsync(new ConfirmAuthenticatorCommand(AccountOf(context), request.Code), context.RequestAborted).ConfigureAwait(false), codes => new { recoveryCodes = codes }));
        manage.MapPost("authenticator/disable", async (PasswordRequest request, ICommandHandler<DisableAuthenticatorCommand> handler, HttpContext context) =>
            NoContent(await handler.HandleAsync(new DisableAuthenticatorCommand(AccountOf(context), request.Password), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
        manage.MapPost("authenticator/recovery-codes", async (CodeRequest request, ICommandHandler<RegenerateRecoveryCodesCommand, IReadOnlyList<string>> handler, HttpContext context) =>
            Ok(await handler.HandleAsync(new RegenerateRecoveryCodesCommand(AccountOf(context), request.Code), context.RequestAborted).ConfigureAwait(false), codes => new { recoveryCodes = codes }));
        manage.MapGet("passkeys", async (IQueryHandler<ListPasskeysQuery, IReadOnlyList<PasskeyDto>> handler, HttpContext context) =>
            Ok(await handler.HandleAsync(new ListPasskeysQuery(AccountOf(context)), context.RequestAborted).ConfigureAwait(false)));
        manage.MapPost("passkeys/options", PasskeyCreationOptionsAsync).AddEndpointFilter<StepUpFilter>();
        manage.MapPost("passkeys", AddPasskeyAsync).AddEndpointFilter<StepUpFilter>();
        manage.MapDelete("passkeys/{passkeyId}", async (string passkeyId, ICommandHandler<RemovePasskeyCommand> handler, HttpContext context) =>
            NoContent(await handler.HandleAsync(new RemovePasskeyCommand(AccountOf(context), passkeyId), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();

        return endpoints;
    }

    // ---- Hosted-UI forms -----------------------------------------------------------------------------------------------

    private static async Task<IResult> LoginAsync(HttpContext context, ICommandHandler<PasswordSignInCommand, LocalSignInResult> handler, IAntiforgery antiforgery)
    {
        if (!await antiforgery.IsRequestValidAsync(context).ConfigureAwait(false))
        {
            return TypedResults.BadRequest();
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
        var email = form["email"].ToString();
        var returnUrl = LocalOrRoot(form["returnUrl"].ToString());

        var result = await handler.HandleAsync(new PasswordSignInCommand(email, form["password"].ToString()), context.RequestAborted).ConfigureAwait(false);
        if (result.IsFailure)
        {
            return BackToLogin(returnUrl, email, "signin_failed");
        }

        switch (result.Value.Status)
        {
            case LocalSignInStatus.SignedIn:
                await SignInAsync(context, result.Value).ConfigureAwait(false);
                return Results.Redirect(returnUrl);
            case LocalSignInStatus.SecondFactorRequired:
                var settings = context.RequestServices.GetRequiredService<IOptions<LocalAccountOptions>>().Value;
                var time = context.RequestServices.GetRequiredService<TimeProvider>();
                var expires = time.GetUtcNow() + settings.SecondFactorWindow;
                var payload = string.Create(CultureInfo.InvariantCulture, $"{result.Value.AccountId}|{expires.ToUnixTimeSeconds()}");
                context.Response.Cookies.Append(SecondFactorCookie, Protector(context, SecondFactorCookie).Protect(payload), CookieOptions(context, expires));
                return Results.Redirect($"{CodePage}?returnUrl={Uri.EscapeDataString(returnUrl)}");
            case LocalSignInStatus.LockedOut:
                return BackToLogin(returnUrl, email, "locked_out");
            case LocalSignInStatus.EmailNotVerified:
                return BackToLogin(returnUrl, email, "email_not_verified");
            case LocalSignInStatus.AccountInactive:
                return BackToLogin(returnUrl, email, "account_inactive");
            case LocalSignInStatus.SsoRequired:
                return BackToLogin(returnUrl, email, "sso_required");
            default:
                return BackToLogin(returnUrl, email, "invalid_credentials");
        }
    }

    private static async Task<IResult> CodeAsync(HttpContext context, ICommandHandler<SecondFactorCommand, LocalSignInResult> handler, IAntiforgery antiforgery, TimeProvider time)
    {
        if (!await antiforgery.IsRequestValidAsync(context).ConfigureAwait(false))
        {
            return TypedResults.BadRequest();
        }

        var form = await context.Request.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
        var returnUrl = LocalOrRoot(form["returnUrl"].ToString());

        if (PendingAccount(context, time) is not { } accountId)
        {
            return BackToLogin(returnUrl, null, "signin_expired");
        }

        var recovery = !string.IsNullOrWhiteSpace(form["recoveryCode"].ToString());
        var code = recovery ? form["recoveryCode"].ToString() : form["code"].ToString();
        var result = await handler.HandleAsync(new SecondFactorCommand(accountId, code, recovery), context.RequestAborted).ConfigureAwait(false);

        if (result.IsSuccess && result.Value.Status == LocalSignInStatus.SignedIn)
        {
            context.Response.Cookies.Delete(SecondFactorCookie, CookieOptions(context, DateTimeOffset.UnixEpoch));
            await SignInAsync(context, result.Value).ConfigureAwait(false);
            return Results.Redirect(returnUrl);
        }

        var error = result.IsSuccess && result.Value.Status == LocalSignInStatus.LockedOut ? "locked_out" : "invalid_code";
        return Results.Redirect($"{CodePage}?returnUrl={Uri.EscapeDataString(returnUrl)}&error={error}");
    }

    // ---- Passkeys ------------------------------------------------------------------------------------------------------

    private static async Task<IResult> PasskeyLoginOptionsAsync(HttpContext context, IPasskeyHandler<PasskeyUser> passkeys, TimeProvider time)
    {
        var options = await passkeys.MakeRequestOptionsAsync(null, context).ConfigureAwait(false);
        SaveState(context, options.AssertionState, time);
        return Results.Content(options.RequestOptionsJson, "application/json");
    }

    private static async Task<IResult> PasskeyLoginAsync(
        PasskeyRequest request,
        HttpContext context,
        IPasskeyHandler<PasskeyUser> passkeys,
        ICommandHandler<PasskeySignInCommand, LocalSignInResult> handler,
        TimeProvider time)
    {
        var state = TakeState(context, time);
        var assertion = await passkeys.PerformAssertionAsync(new PasskeyAssertionContext
        {
            CredentialJson = request.Credential.GetRawText(),
            AssertionState = state,
            HttpContext = context,
        }).ConfigureAwait(false);

        if (!assertion.Succeeded || !Guid.TryParse(assertion.User.Id, out var accountId))
        {
            return Problem(StatusCodes.Status401Unauthorized, LocalAccountErrors.InvalidCredentials, "The passkey sign-in didn't work.");
        }

        var result = await handler.HandleAsync(new PasskeySignInCommand(accountId, ToData(assertion.Passkey)), context.RequestAborted).ConfigureAwait(false);
        if (result.IsSuccess && result.Value.Status == LocalSignInStatus.SsoRequired)
        {
            return Problem(StatusCodes.Status403Forbidden, LocalAccountErrors.SsoRequired, "Your organization requires signing in with its identity provider.");
        }

        if (result.IsFailure || result.Value.Status != LocalSignInStatus.SignedIn)
        {
            return Problem(StatusCodes.Status401Unauthorized, LocalAccountErrors.InvalidCredentials, "The passkey sign-in didn't work.");
        }

        await SignInAsync(context, result.Value).ConfigureAwait(false);
        return TypedResults.Ok(new { redirect = LocalOrRoot(request.ReturnUrl) });
    }

    private static async Task<IResult> PasskeyCreationOptionsAsync(HttpContext context, IPasskeyHandler<PasskeyUser> passkeys, UserManager<PasskeyUser> users, TimeProvider time)
    {
        if (await users.FindByIdAsync(AccountOf(context).ToString()).ConfigureAwait(false) is not { } user)
        {
            return Problem(StatusCodes.Status403Forbidden, LocalAccountErrors.AccountInactive, "The account is not active.");
        }

        var options = await passkeys.MakeCreationOptionsAsync(new PasskeyUserEntity { Id = user.Id, Name = user.Email, DisplayName = user.DisplayName ?? user.Email }, context).ConfigureAwait(false);
        SaveState(context, options.AttestationState, time);
        return Results.Content(options.CreationOptionsJson, "application/json");
    }

    private static async Task<IResult> AddPasskeyAsync(
        PasskeyRequest request,
        HttpContext context,
        IPasskeyHandler<PasskeyUser> passkeys,
        ICommandHandler<AddPasskeyCommand, PasskeyDto> handler,
        TimeProvider time)
    {
        var attestation = await passkeys.PerformAttestationAsync(new PasskeyAttestationContext
        {
            CredentialJson = request.Credential.GetRawText(),
            AttestationState = TakeState(context, time),
            HttpContext = context,
        }).ConfigureAwait(false);

        var accountId = AccountOf(context);
        if (!attestation.Succeeded || attestation.UserEntity.Id != accountId.ToString())
        {
            return Problem(StatusCodes.Status400BadRequest, "passkey_invalid", attestation.Failure?.Message ?? "The passkey could not be verified.");
        }

        var data = ToData(attestation.Passkey) with { Name = string.IsNullOrWhiteSpace(request.Name) ? null : request.Name.Trim() };
        return Ok(await handler.HandleAsync(new AddPasskeyCommand(accountId, data), context.RequestAborted).ConfigureAwait(false));
    }

    private static PasskeyData ToData(UserPasskeyInfo passkey) => new(
        passkey.CredentialId, passkey.PublicKey, passkey.Name, passkey.CreatedAt, passkey.SignCount, passkey.Transports,
        passkey.IsUserVerified, passkey.IsBackupEligible, passkey.IsBackedUp, passkey.AttestationObject, passkey.ClientDataJson);

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private static async Task SignInAsync(HttpContext context, LocalSignInResult result)
    {
        var options = context.RequestServices.GetRequiredService<IOptions<TokenServerOptions>>().Value;
        var names = context.RequestServices.GetService<ClaimNames>() ?? ClaimNames.Default;
        var now = context.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow();
        var principal = SignInPrincipal.Create(result.AccountId!.Value, new AuthenticationStrength(result.Methods ?? []), now, names, options.SignInScheme);
        await context.SignInAsync(options.SignInScheme, principal).ConfigureAwait(false);
    }

    private static Guid? PendingAccount(HttpContext context, TimeProvider time)
    {
        if (!context.Request.Cookies.TryGetValue(SecondFactorCookie, out var value) || string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            var parts = Protector(context, SecondFactorCookie).Unprotect(value).Split('|');
            return parts.Length == 2
                && Guid.TryParse(parts[0], out var accountId)
                && long.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var expires)
                && DateTimeOffset.FromUnixTimeSeconds(expires) > time.GetUtcNow()
                    ? accountId
                    : null;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }

    private static void SaveState(HttpContext context, string? state, TimeProvider time)
    {
        var expires = time.GetUtcNow().AddMinutes(5);
        context.Response.Cookies.Append(PasskeyStateCookie, Protector(context, PasskeyStateCookie).Protect(state ?? string.Empty), CookieOptions(context, expires));
    }

    private static string? TakeState(HttpContext context, TimeProvider time)
    {
        context.Response.Cookies.Delete(PasskeyStateCookie, CookieOptions(context, DateTimeOffset.UnixEpoch));
        if (!context.Request.Cookies.TryGetValue(PasskeyStateCookie, out var value) || string.IsNullOrEmpty(value))
        {
            return null;
        }

        try
        {
            return Protector(context, PasskeyStateCookie).Unprotect(value);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }

    private static ITimeLimitedDataProtector Protector(HttpContext context, string purpose) =>
        context.RequestServices.GetRequiredService<IDataProtectionProvider>().CreateProtector("JeffOps.LocalAccounts." + purpose).ToTimeLimitedDataProtector();

    private static CookieOptions CookieOptions(HttpContext context, DateTimeOffset expires) => new()
    {
        HttpOnly = true,
        Secure = context.Request.IsHttps,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        Expires = expires,
        IsEssential = true,
    };

    private static Guid AccountOf(HttpContext context) =>
        Guid.Parse(context.User.FindFirst((context.RequestServices.GetService<ClaimNames>() ?? ClaimNames.Default).Subject)!.Value);

    private static IResult BackToLogin(string returnUrl, string? email, string error) =>
        Results.Redirect($"{LoginPage}?returnUrl={Uri.EscapeDataString(returnUrl)}&error={error}" + (string.IsNullOrEmpty(email) ? string.Empty : $"&email={Uri.EscapeDataString(email)}"));

    internal static string LocalOrRoot(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//", StringComparison.Ordinal) && !returnUrl.StartsWith("/\\", StringComparison.Ordinal)
            ? returnUrl
            : "/";

    private static IResult Accepted(Result result) => result.IsSuccess ? TypedResults.Accepted((string?)null) : Problem(result.Error);

    private static IResult NoContent(Result result) => result.IsSuccess ? TypedResults.NoContent() : Problem(result.Error);

    private static IResult Ok<T>(Result<T> result) => result.IsSuccess ? TypedResults.Ok(result.Value) : Problem(result.Error);

    private static IResult Ok<T, TBody>(Result<T> result, Func<T, TBody> body) => result.IsSuccess ? TypedResults.Ok(body(result.Value)) : Problem(result.Error);

    private static IResult Problem(Error error) => error.Type == ErrorType.Validation
        ? TypedResults.ValidationProblem(
            error.Failures.GroupBy(failure => failure.Property).ToDictionary(group => group.Key, group => group.Select(failure => failure.Message).ToArray()),
            detail: error.Message,
            extensions: new Dictionary<string, object?> { ["code"] = error.Code })
        : Problem(
            error.Type switch
            {
                ErrorType.Forbidden => StatusCodes.Status403Forbidden,
                ErrorType.NotFound => StatusCodes.Status404NotFound,
                ErrorType.Conflict => StatusCodes.Status409Conflict,
                ErrorType.Unauthorized => StatusCodes.Status401Unauthorized,
                _ => StatusCodes.Status400BadRequest,
            },
            error.Code,
            error.Message);

    private static IResult Problem(int status, string code, string detail) =>
        TypedResults.Problem(detail: detail, statusCode: status, extensions: new Dictionary<string, object?> { ["code"] = code });
}

/// <summary>Every local-account route answers 404 while local accounts are off (by default, outside Development).</summary>
internal sealed class EnabledFilter : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var enabled = context.HttpContext.RequestServices.GetServices<InteractiveSignInMethod>().Any(method => method.Name == "password" && method.Enabled);
        return enabled ? next(context) : ValueTask.FromResult<object?>(TypedResults.NotFound());
    }
}

/// <summary>Credentials are managed by their owner in their own session: never under impersonation or a delegated session.</summary>
internal sealed class OwnSessionFilter : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var user = context.HttpContext.User;
        var names = context.HttpContext.RequestServices.GetService<ClaimNames>() ?? ClaimNames.Default;
        var own = AccessContextReader.IsInteractiveUser(user, names)
            && !AccessContextReader.IsImpersonation(user, names)
            && !AccessContextReader.Read(user, names).IsDelegated
            && !user.HasClaim(claim => claim.Type == names.PatCeiling || claim.Type == names.DelegationScope);
        return own
            ? next(context)
            : ValueTask.FromResult<object?>(TypedResults.Problem(
                detail: "Credentials can only be managed in your own session.",
                statusCode: StatusCodes.Status403Forbidden,
                extensions: new Dictionary<string, object?> { ["code"] = "home_session_required" }));
    }
}

/// <summary>Adding or removing sign-in credentials needs a stepped-up session (RFC 9470 challenge).</summary>
internal sealed class StepUpFilter : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var http = context.HttpContext;
        if (AccessContextReader.IsSteppedUp(http.User, http.RequestServices.GetService<ClaimNames>() ?? ClaimNames.Default))
        {
            return next(context);
        }

        http.Response.Headers.WWWAuthenticate =
            "Bearer error=\"insufficient_user_authentication\", error_description=\"A multi-factor sign-in is required.\"";
        return ValueTask.FromResult<object?>(TypedResults.Problem(
            detail: "This change requires a multi-factor sign-in (step-up).",
            statusCode: StatusCodes.Status403Forbidden,
            extensions: new Dictionary<string, object?> { ["code"] = "step_up_required" }));
    }
}

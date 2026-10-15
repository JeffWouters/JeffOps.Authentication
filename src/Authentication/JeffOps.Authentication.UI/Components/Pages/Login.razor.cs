using JeffOps.Authentication.Application.Federation;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authentication.UI.Components.Pages;

/// <summary>The hosted login page: home realm discovery by email, and the configured providers.</summary>
public sealed partial class Login
{
    /// <summary>
    /// The page's own policy: its stylesheet, nothing else loads; forms may go to this server and, through redirects, to
    /// identity providers (browsers apply form-action to the redirect chain).
    /// </summary>
    internal const string ContentSecurityPolicy =
        "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self' https:; frame-ancestors 'none'; base-uri 'self'";

    private static readonly Dictionary<string, string> Messages = new(StringComparer.Ordinal)
    {
        ["domain_not_allowed"] = "Accounts from your organization can't sign in here.",
        ["registration_closed"] = "There is no account for this sign-in. Ask an administrator to invite you.",
        ["email_required"] = "Your identity provider didn't share an email address.",
        ["mfa_required"] = "Sign in with multi-factor authentication to continue.",
        ["account_inactive"] = "This account is disabled.",
        ["invalid_credentials"] = "The email or password is wrong.",
        ["locked_out"] = "Too many attempts. Wait a moment and try again.",
        ["email_not_verified"] = "Confirm your email address first: use the link we sent you.",
        ["signin_expired"] = "That took too long. Sign in again.",
    };

    [SupplyParameterFromQuery(Name = "returnUrl")]
    public string? ReturnUrl { get; set; }

    [SupplyParameterFromQuery(Name = "email")]
    public string? Email { get; set; }

    [SupplyParameterFromQuery(Name = "error")]
    public string? Error { get; set; }

    [CascadingParameter]
    public HttpContext? HttpContext { get; set; }

    private IReadOnlyList<ExternalProviderInfo> Providers { get; set; } = [];

    private string? ErrorMessage { get; set; }

    private string SafeReturnUrl { get; set; } = "/";

    /// <summary>Where the password form posts, when local accounts are on.</summary>
    private string? PasswordAction { get; set; }

    protected override void OnInitialized()
    {
        if (HttpContext is { Response.HasStarted: false } http)
        {
            http.Response.Headers.ContentSecurityPolicy = ContentSecurityPolicy;
            http.Response.Headers.CacheControl = "no-store";
        }

        SafeReturnUrl = IsLocal(ReturnUrl) ? ReturnUrl! : "/";
        Providers = [.. Mappers.SelectMany(mapper => mapper.Providers).DistinctBy(provider => provider.Name)];
        PasswordAction = SignInMethods.FirstOrDefault(method => method is { Name: "password", Enabled: true })?.FormAction;
        ErrorMessage = Error is null ? null : Messages.GetValueOrDefault(Error, "Signing in didn't work. Try again.");
    }

    private string ProviderUrl(ExternalProviderInfo provider) =>
        $"/signin/{Uri.EscapeDataString(provider.Name)}?returnUrl={Uri.EscapeDataString(SafeReturnUrl)}";

    private static bool IsLocal(string? url) =>
        !string.IsNullOrEmpty(url) && url.StartsWith('/') && !url.StartsWith("//", StringComparison.Ordinal) && !url.StartsWith("/\\", StringComparison.Ordinal);
}

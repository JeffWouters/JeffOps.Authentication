using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authentication.UI.Components.Pages;

/// <summary>The second step of a local sign-in: an authenticator or recovery code.</summary>
public sealed partial class LoginCode
{
    [SupplyParameterFromQuery(Name = "returnUrl")]
    public string? ReturnUrl { get; set; }

    [SupplyParameterFromQuery(Name = "error")]
    public string? Error { get; set; }

    [CascadingParameter]
    public HttpContext? HttpContext { get; set; }

    private string SafeReturnUrl { get; set; } = "/";

    private string? ErrorMessage { get; set; }

    protected override void OnInitialized()
    {
        if (HttpContext is { Response.HasStarted: false } http)
        {
            http.Response.Headers.ContentSecurityPolicy = Login.ContentSecurityPolicy;
            http.Response.Headers.CacheControl = "no-store";
        }

        SafeReturnUrl = !string.IsNullOrEmpty(ReturnUrl) && ReturnUrl.StartsWith('/') && !ReturnUrl.StartsWith("//", StringComparison.Ordinal) && !ReturnUrl.StartsWith("/\\", StringComparison.Ordinal)
            ? ReturnUrl
            : "/";
        ErrorMessage = Error switch
        {
            null => null,
            "locked_out" => "Too many attempts. Wait a moment and try again.",
            _ => "That code didn't work. Try again.",
        };
    }
}

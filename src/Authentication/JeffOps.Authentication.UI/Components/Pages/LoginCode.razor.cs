using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authentication.UI.Components.Pages;

/// <summary>The second step of a local sign-in: an authenticator or recovery code.</summary>
public sealed partial class LoginCode
{
    /// <summary>
    /// Where to go after signing in, from the <c>returnUrl</c> query value. Only a local path is honoured; anything else falls
    /// back to <c>/</c>.
    /// </summary>
    [SupplyParameterFromQuery(Name = "returnUrl")]
    public string? ReturnUrl { get; set; }

    /// <summary>The error code of a failed attempt, from the <c>error</c> query value, for example <c>locked_out</c>.</summary>
    [SupplyParameterFromQuery(Name = "error")]
    public string? Error { get; set; }

    /// <summary>The current request, cascaded during static server rendering; used to set the response's security headers.</summary>
    [CascadingParameter]
    public HttpContext? HttpContext { get; set; }

    private string SafeReturnUrl { get; set; } = "/";

    private string? ErrorMessage { get; set; }

    /// <inheritdoc />
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

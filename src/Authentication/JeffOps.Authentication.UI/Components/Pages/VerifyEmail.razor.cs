using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authentication.UI.Components.Pages;

/// <summary>Completes email verification from the emailed link, after the user presses the button.</summary>
public sealed partial class VerifyEmail
{
    /// <summary>The token from the emailed link (the <c>token</c> query value).</summary>
    [SupplyParameterFromQuery(Name = "token")]
    public string? Token { get; set; }

    /// <summary>Whether the address was verified, from the <c>done</c> query value.</summary>
    [SupplyParameterFromQuery(Name = "done")]
    public string? DoneFlag { get; set; }

    /// <summary>The error of a failed attempt, from the <c>error</c> query value.</summary>
    [SupplyParameterFromQuery(Name = "error")]
    public string? Error { get; set; }

    /// <summary>The current request, cascaded during static server rendering; used to set the response's security headers.</summary>
    [CascadingParameter]
    public HttpContext? HttpContext { get; set; }

    private bool Done => DoneFlag == "1";

    private bool PasswordsEnabled => SignInMethods.Any(method => method is { Name: "password", Enabled: true });

    /// <inheritdoc />
    protected override void OnInitialized() => Login.ApplySecurityHeaders(HttpContext);
}

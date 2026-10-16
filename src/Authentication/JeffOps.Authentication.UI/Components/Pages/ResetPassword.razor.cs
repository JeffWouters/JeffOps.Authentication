using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authentication.UI.Components.Pages;

/// <summary>Sets a new password from the emailed link's token.</summary>
public sealed partial class ResetPassword
{
    /// <summary>The token from the emailed link (the <c>token</c> query value).</summary>
    [SupplyParameterFromQuery(Name = "token")]
    public string? Token { get; set; }

    /// <summary>Whether the password was set, from the <c>done</c> query value.</summary>
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

    private string? ErrorMessage => Error switch
    {
        null => null,
        "weak_password" => "Choose a longer password that isn't commonly used.",
        _ => "This link is invalid or has expired. Ask for a new one.",
    };

    /// <inheritdoc />
    protected override void OnInitialized() => Login.ApplySecurityHeaders(HttpContext);
}

using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authentication.UI.Components.Pages;

/// <summary>Asks for a password reset link. The answer is the same whether or not the address has an account.</summary>
public sealed partial class ForgotPassword
{
    /// <summary>Whether the link was requested, from the <c>sent</c> query value.</summary>
    [SupplyParameterFromQuery(Name = "sent")]
    public string? SentFlag { get; set; }

    /// <summary>The current request, cascaded during static server rendering; used to set the response's security headers.</summary>
    [CascadingParameter]
    public HttpContext? HttpContext { get; set; }

    private bool Sent => SentFlag == "1";

    private bool PasswordsEnabled => SignInMethods.Any(method => method is { Name: "password", Enabled: true });

    /// <inheritdoc />
    protected override void OnInitialized() => Login.ApplySecurityHeaders(HttpContext);
}

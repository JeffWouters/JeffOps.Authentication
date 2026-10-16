using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authentication.UI.Components.Pages;

/// <summary>The device flow's confirmation page (RFC 8628): enter the device's code, see which application asks, allow or deny.</summary>
public sealed partial class Device
{
    /// <summary>The code the device shows, from the <c>user_code</c> query value; pre-fills the form.</summary>
    [SupplyParameterFromQuery(Name = "user_code")]
    public string? UserCode { get; set; }

    /// <summary>
    /// The display name of the application asking for access, from the <c>client</c> query value. Set once the code has been
    /// checked; its presence switches the page from entering a code to allowing or denying.
    /// </summary>
    [SupplyParameterFromQuery(Name = "client")]
    public string? Client { get; set; }

    /// <summary>The outcome of a decision, from the <c>result</c> query value: <c>approved</c> or <c>denied</c>.</summary>
    [SupplyParameterFromQuery(Name = "result")]
    public string? Result { get; set; }

    /// <summary>Why the last attempt failed, from the <c>error</c> query value, for example <c>invalid_code</c>.</summary>
    [SupplyParameterFromQuery(Name = "error")]
    public string? Error { get; set; }

    /// <summary>The current request, cascaded during static server rendering; used to set the response's security headers.</summary>
    [CascadingParameter]
    public HttpContext? HttpContext { get; set; }

    private string? Message { get; set; }

    /// <inheritdoc />
    protected override void OnInitialized()
    {
        if (HttpContext is { Response.HasStarted: false } http)
        {
            http.Response.Headers.ContentSecurityPolicy = Login.ContentSecurityPolicy;
            http.Response.Headers.CacheControl = "no-store";
        }

        Message = (Result, Error) switch
        {
            ("approved", _) => "Done. You can go back to your device.",
            ("denied", _) => "Denied. The device was not connected.",
            (_, "invalid_code") => "That code is not valid or has expired. Check the device and try again.",
            (_, not null) => "That didn't work. Try again.",
            _ => null,
        };
    }
}

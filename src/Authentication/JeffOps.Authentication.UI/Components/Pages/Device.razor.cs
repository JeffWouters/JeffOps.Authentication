using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authentication.UI.Components.Pages;

/// <summary>The device flow's confirmation page (RFC 8628): enter the device's code, see which application asks, allow or deny.</summary>
public sealed partial class Device
{
    [SupplyParameterFromQuery(Name = "user_code")]
    public string? UserCode { get; set; }

    [SupplyParameterFromQuery(Name = "client")]
    public string? Client { get; set; }

    [SupplyParameterFromQuery(Name = "result")]
    public string? Result { get; set; }

    [SupplyParameterFromQuery(Name = "error")]
    public string? Error { get; set; }

    [CascadingParameter]
    public HttpContext? HttpContext { get; set; }

    private string? Message { get; set; }

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

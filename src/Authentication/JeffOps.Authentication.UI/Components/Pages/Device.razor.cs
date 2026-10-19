using JeffOps.Authentication.Application.Sessions;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authentication.UI.Components.Pages;

/// <summary>The device flow's confirmation page (RFC 8628): enter the device's code, see which application asks, allow or deny.</summary>
public sealed partial class Device
{
    /// <summary>The code the device shows, from the <c>user_code</c> query value; pre-fills the form.</summary>
    [SupplyParameterFromQuery(Name = "user_code")]
    public string? UserCode { get; set; }

    /// <summary>
    /// The token server's sealed consent ticket for the code (<see cref="DeviceConsentTicket"/>), from the <c>consent</c>
    /// query value; posted back with the decision. The application's name is shown only from it, never from the query.
    /// </summary>
    [SupplyParameterFromQuery(Name = "consent")]
    public string? Consent { get; set; }

    /// <summary>The registered name of the application the code was issued to, once the code has been checked.</summary>
    private string? Client { get; set; }

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

        Client = ClientNameFromTicket();

        Message = (Result, Error) switch
        {
            ("approved", _) => "Done. You can go back to your device.",
            ("denied", _) => "Denied. The device was not connected.",
            (_, "invalid_code") => "That code is not valid or has expired. Check the device and try again.",
            (_, "provider_not_allowed") => "This application needs another way of signing in. Sign out, sign in with one of its options, and try again.",
            (_, not null) => "That didn't work. Try again.",
            _ => null,
        };
    }

    private string? ClientNameFromTicket()
    {
        if (string.IsNullOrEmpty(Consent) || HttpContext?.RequestServices.GetService(typeof(IDataProtectionProvider)) is not IDataProtectionProvider provider)
        {
            return null;
        }

        try
        {
            var json = provider.CreateProtector(DeviceConsentTicket.Purpose).ToTimeLimitedDataProtector().Unprotect(Consent);
            return DeviceConsentTicket.Deserialize(json) is { } ticket && string.Equals(ticket.UserCode, UserCode, StringComparison.Ordinal)
                ? ticket.DisplayName
                : null;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }
}

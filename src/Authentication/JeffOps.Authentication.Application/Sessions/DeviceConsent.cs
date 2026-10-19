using System.Text.Json;

namespace JeffOps.Authentication.Application.Sessions;

/// <summary>
/// What the device-flow confirmation page may show and approve (RFC 8628 §5.4): the user code, the client it was issued
/// to, and that client's registered name, sealed by the token server (Data Protection, ten minutes). The page names the
/// client only from a ticket for the same code, and an approval counts only when the ticket names the code's own client,
/// so a link can't present another application's name.
/// </summary>
public sealed record DeviceConsentTicket(string UserCode, string ClientId, string DisplayName)
{
    /// <summary>The Data Protection purpose of the sealed ticket.</summary>
    public const string Purpose = "JeffOps.Authentication.DeviceConsent.v1";

    /// <summary>How long a ticket stays valid.</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    public string Serialize() => JsonSerializer.Serialize(this);

    /// <summary>The ticket in <paramref name="json"/>, or null when it isn't one.</summary>
    public static DeviceConsentTicket? Deserialize(string? json)
    {
        if (string.IsNullOrEmpty(json))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<DeviceConsentTicket>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

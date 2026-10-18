using System.Globalization;
using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Domain.Sessions;

namespace JeffOps.Authentication.Application.Sessions;

/// <summary>
/// The principal the login UI or a federation callback signs in with the sign-in scheme. The authorize endpoint reads it:
/// the account id, how the user authenticated, and when. Use <see cref="Create"/> so the claims match.
/// </summary>
public static class SignInPrincipal
{
    /// <summary>
    /// The provider the user signed in through (a provider name, or <c>local</c>). Kept in the sign-in cookie only, never in
    /// tokens: the authorize endpoint checks it against the client's <c>Providers</c>.
    /// </summary>
    public const string ProviderClaim = "jeffops:idp";

    public static ClaimsPrincipal Create(Guid accountId, AuthenticationStrength strength, DateTimeOffset signedInAt, ClaimNames names, string authenticationType, string? provider = null)
    {
        ArgumentNullException.ThrowIfNull(strength);
        ArgumentNullException.ThrowIfNull(names);

        var claims = new List<Claim>
        {
            new(names.Subject, accountId.ToString()),
            new(names.AuthenticationTime, signedInAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),

            // A new session per sign-in: its tokens carry it (sid), and signing out ends exactly this one.
            new(names.SessionId, Guid.NewGuid().ToString("N")),
        };
        claims.AddRange(strength.Methods.Select(method => new Claim(names.AuthenticationMethods, method)));
        if (!string.IsNullOrEmpty(provider))
        {
            claims.Add(new Claim(ProviderClaim, provider));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType, names.Name, "role"));
    }

    /// <summary>The session of a sign-in (or of a token issued for it), or null for one made before sessions had ids.</summary>
    public static string? SessionId(ClaimsPrincipal? principal, ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(names);
        return principal?.FindFirst(names.SessionId)?.Value is { Length: > 0 and <= 64 } sessionId ? sessionId : null;
    }

    /// <summary>The provider a sign-in came through, or null for one made before sign-ins recorded it.</summary>
    public static string? ProviderOf(ClaimsPrincipal? principal) => principal?.FindFirst(ProviderClaim)?.Value;

    public static DateTimeOffset? SignedInAt(ClaimsPrincipal? principal, ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(names);
        return long.TryParse(principal?.FindFirst(names.AuthenticationTime)?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
    }
}

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
    public static ClaimsPrincipal Create(Guid accountId, AuthenticationStrength strength, DateTimeOffset signedInAt, ClaimNames names, string authenticationType)
    {
        ArgumentNullException.ThrowIfNull(strength);
        ArgumentNullException.ThrowIfNull(names);

        var claims = new List<Claim>
        {
            new(names.Subject, accountId.ToString()),
            new(names.AuthenticationTime, signedInAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
        };
        claims.AddRange(strength.Methods.Select(method => new Claim(names.AuthenticationMethods, method)));

        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticationType, names.Name, "role"));
    }

    public static DateTimeOffset? SignedInAt(ClaimsPrincipal? principal, ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(names);
        return long.TryParse(principal?.FindFirst(names.AuthenticationTime)?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var seconds)
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;
    }
}

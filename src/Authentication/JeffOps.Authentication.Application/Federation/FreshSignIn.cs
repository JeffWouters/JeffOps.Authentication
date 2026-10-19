using System.Globalization;

namespace JeffOps.Authentication.Application.Federation;

/// <summary>
/// A sign-in a client asked to be fresh (<c>prompt=login</c>, <c>max_age</c>). The authorize endpoint sends the user to sign
/// in with the time the new sign-in must follow in the return URL (<see cref="Parameter"/>); external providers are then
/// asked to authenticate the user again (<c>prompt=login</c> and <c>max_age</c>, SAML <c>ForceAuthn</c>), and an answer
/// saying the provider authenticated the user before that time is refused: a provider's single sign-on session can't stand
/// in for the re-authentication the client asked for.
/// </summary>
public static class FreshSignIn
{
    /// <summary>The return URL parameter holding the time (Unix seconds) the sign-in must follow.</summary>
    public const string Parameter = "jeffops_signed_in_after";

    /// <summary>The error a provider's stale authentication gets.</summary>
    public const string ReauthenticationRequired = "reauthentication_required";

    /// <summary>How far a provider's clock may be behind this server's.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(1);

    /// <summary>
    /// The time in a <see cref="Parameter"/> value, or null when there is none or it isn't valid (a time to come can't be
    /// required: nobody could ever meet it).
    /// </summary>
    public static DateTimeOffset? Parse(string? value, DateTimeOffset now) =>
        long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
        && seconds <= now.ToUnixTimeSeconds()
            ? DateTimeOffset.FromUnixTimeSeconds(seconds)
            : null;

    /// <summary>The time a sign-in must follow, from a local return URL's <see cref="Parameter"/>; null when it has none.</summary>
    public static DateTimeOffset? RequiredAfter(string? returnUrl, DateTimeOffset now)
    {
        var start = returnUrl?.IndexOf('?', StringComparison.Ordinal) ?? -1;
        if (returnUrl is null || start < 0)
        {
            return null;
        }

        var query = returnUrl[(start + 1)..];
        if (query.IndexOf('#', StringComparison.Ordinal) is var fragment and >= 0)
        {
            query = query[..fragment];
        }

        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = pair.IndexOf('=', StringComparison.Ordinal);
            if (separator > 0 && string.Equals(Uri.UnescapeDataString(pair[..separator]), Parameter, StringComparison.Ordinal))
            {
                return Parse(Uri.UnescapeDataString(pair[(separator + 1)..]), now);
            }
        }

        return null;
    }

    /// <summary>The <c>max_age</c> (seconds) to ask a provider for, to authenticate after <paramref name="requiredAfter"/>.</summary>
    public static long MaxAge(DateTimeOffset requiredAfter, DateTimeOffset now) =>
        Math.Max(0, (long)(now - requiredAfter).TotalSeconds);

    /// <summary>
    /// Whether a provider's authentication time meets the requirement: true without one; false when the provider says it
    /// authenticated the user earlier. A provider that doesn't say was asked with <c>prompt=login</c>, which it must honour.
    /// </summary>
    public static bool ProviderAuthenticatedInTime(DateTimeOffset? providerAuthenticatedAt, DateTimeOffset? requiredAfter) =>
        requiredAfter is not { } required || providerAuthenticatedAt is not { } at || at >= required - ClockSkew;

    /// <summary>An <c>auth_time</c> claim value (Unix seconds) as a time; null when absent or not a number.</summary>
    public static DateTimeOffset? AuthTime(string? value) =>
        long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) ? DateTimeOffset.FromUnixTimeSeconds(seconds) : null;
}

namespace JeffOps.Authentication.Domain.Sessions;

/// <summary>
/// How strongly a sign-in authenticated the user, as RFC 8176 authentication method references (<c>amr</c>). External
/// providers map their own signals (amr, acr, acrs, SAML contexts) into this form; the token server never reads
/// provider-specific claims (docs/DESIGN.md §8.1).
/// </summary>
public sealed record AuthenticationStrength
{
    public const string MultiFactor = "mfa";

    public AuthenticationStrength(IEnumerable<string> methods)
    {
        ArgumentNullException.ThrowIfNull(methods);
        Methods = [.. methods.Where(method => !string.IsNullOrWhiteSpace(method)).Select(method => method.Trim()).Distinct(StringComparer.Ordinal)];
    }

    public static AuthenticationStrength None { get; } = new([]);

    public static AuthenticationStrength Password { get; } = new(["pwd"]);

    public IReadOnlyList<string> Methods { get; }

    public bool IsMultiFactor => Methods.Contains(MultiFactor, StringComparer.Ordinal);

    /// <summary>Adds <see cref="MultiFactor"/> when the provider asserted it another way (for example an accepted auth context).</summary>
    public AuthenticationStrength WithMultiFactor() => IsMultiFactor ? this : new([.. Methods, MultiFactor]);
}

/// <summary>The platform's strong-authentication policy.</summary>
/// <param name="RequireForSignIn">Refuse sign-ins (and refreshes of sessions) that were not multi-factor.</param>
/// <param name="RequireForSensitiveActions">Sensitive actions need a multi-factor sign-in (step-up).</param>
public sealed record MfaPolicy(bool RequireForSignIn, bool RequireForSensitiveActions)
{
    /// <summary>Whether a session of this strength may perform step-up-protected actions.</summary>
    public bool SatisfiesStepUp(AuthenticationStrength strength)
    {
        ArgumentNullException.ThrowIfNull(strength);
        return !RequireForSensitiveActions || strength.IsMultiFactor;
    }

    public bool AllowsSignIn(AuthenticationStrength strength)
    {
        ArgumentNullException.ThrowIfNull(strength);
        return !RequireForSignIn || strength.IsMultiFactor;
    }
}

/// <summary>
/// The absolute lifetime of an interactive session, counted from the original sign-in and never extended by refreshing.
/// </summary>
public static class SessionLifetime
{
    public static bool HasExpired(DateTimeOffset signedInAt, DateTimeOffset now, TimeSpan absoluteLifetime) =>
        now - signedInAt >= absoluteLifetime;
}

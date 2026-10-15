namespace JeffOps.Authentication.LocalAccounts.Application;

public enum LocalSignInStatus
{
    SignedIn,

    /// <summary>The password was right; a second factor must follow within the window.</summary>
    SecondFactorRequired,
    Failed,
    LockedOut,
    EmailNotVerified,
    AccountInactive,

    /// <summary>The email's organization requires signing in with its identity provider.</summary>
    SsoRequired,
}

/// <summary>
/// The outcome of a local sign-in step. <see cref="Methods"/> are RFC 8176 <c>amr</c> values for the sign-in principal:
/// <c>pwd</c>; <c>pwd otp mfa</c> after a second factor; <c>hwk</c> or <c>swk</c> (synced) plus <c>user mfa</c> for a
/// user-verified passkey.
/// </summary>
public sealed record LocalSignInResult(LocalSignInStatus Status, Guid? AccountId = null, IReadOnlyList<string>? Methods = null)
{
    public static LocalSignInResult Failed { get; } = new(LocalSignInStatus.Failed);
}

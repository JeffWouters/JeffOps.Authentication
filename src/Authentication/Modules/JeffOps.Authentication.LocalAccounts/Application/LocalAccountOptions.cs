using JeffOps.Authentication.LocalAccounts.Domain;

namespace JeffOps.Authentication.LocalAccounts.Application;

/// <summary>Local accounts (docs/DESIGN.md §8.5). Bound from <see cref="SectionName"/>.</summary>
public sealed class LocalAccountOptions
{
    public const string SectionName = "JeffOps:LocalAccounts";

    /// <summary>
    /// Whether local accounts are on. Null (default) means on in Development only: a production token server never accepts
    /// passwords unless the host decides so explicitly.
    /// </summary>
    public bool? Enabled { get; set; }

    /// <summary>Whether people can create accounts themselves. Default: true.</summary>
    public bool AllowRegistration { get; set; } = true;

    /// <summary>Whether an unverified email blocks password sign-in. Default: true.</summary>
    public bool RequireVerifiedEmail { get; set; } = true;

    public int MinimumPasswordLength { get; set; } = 12;

    /// <summary>PBKDF2-SHA512 iterations for new hashes; older hashes are upgraded at sign-in. Default: 210,000.</summary>
    public int HashIterations { get; set; } = PasswordHasher.DefaultIterations;

    public int LockoutFreeAttempts { get; set; } = LockoutPolicy.Default.FreeAttempts;

    public TimeSpan LockoutBaseDelay { get; set; } = LockoutPolicy.Default.BaseDelay;

    public TimeSpan LockoutMaxDelay { get; set; } = LockoutPolicy.Default.MaxDelay;

    public TimeSpan VerificationTokenLifetime { get; set; } = TimeSpan.FromHours(24);

    public TimeSpan ResetTokenLifetime { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>How long a password sign-in waits for its second factor. Default: 5 minutes.</summary>
    public TimeSpan SecondFactorWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Whether accounts without an authenticator app complete a password sign-in with a six-digit code sent by email. The
    /// code counts as a second factor (<c>otp</c>, <c>mfa</c>); accounts with an authenticator use that instead. Default: false.
    /// </summary>
    public bool EmailCodes { get; set; }

    /// <summary>How long an emailed sign-in code is valid. Default: 10 minutes.</summary>
    public TimeSpan EmailCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    public int RecoveryCodeCount { get; set; } = 10;

    /// <summary>The issuer name authenticator apps show. Default: <c>JeffOps</c>.</summary>
    public string TotpIssuer { get; set; } = "JeffOps";

    /// <summary>The public base address links in emails point to (the token server). Required when emails are sent.</summary>
    public Uri? PublicOrigin { get; set; }

    /// <summary>The page that completes email verification; <c>{0}</c> is the token.</summary>
    public string VerifyEmailPath { get; set; } = "account/verify-email?token={0}";

    /// <summary>The page that sets a new password; <c>{0}</c> is the token.</summary>
    public string ResetPasswordPath { get; set; } = "account/reset-password?token={0}";

    /// <summary>
    /// The WebAuthn relying party id (a registrable domain, for example <c>example.com</c>). Null uses the request's host. Pick
    /// it once: passkeys are bound to it.
    /// </summary>
    public string? PasskeyServerDomain { get; set; }

    /// <summary>
    /// Origins allowed to run passkey ceremonies (for example the SPA's origin when the BFF proxies them). Empty allows only
    /// the token server's own origin.
    /// </summary>
    public IList<string> PasskeyAllowedOrigins { get; } = [];

    public LockoutPolicy Lockout() => new(LockoutFreeAttempts, LockoutBaseDelay, LockoutMaxDelay);

    public string Link(string pathFormat, string token) =>
        new Uri(PublicOrigin ?? new Uri("https://localhost/"), string.Format(System.Globalization.CultureInfo.InvariantCulture, pathFormat, Uri.EscapeDataString(token))).AbsoluteUri;
}

using System.Security.Claims;

namespace JeffOps.Authentication.Application.Sessions;

/// <summary>
/// What a grant decided to issue: the subject, its claims and scopes, and lifetimes. The protocol layer turns it into tokens;
/// the application layer never sees OpenIddict (docs/DESIGN.md §6.1).
/// </summary>
public sealed record IssuedIdentity(string Subject, IReadOnlyList<Claim> Claims, IReadOnlyCollection<string> Scopes)
{
    /// <summary>Overrides the default access-token lifetime, e.g. for PAT exchanges.</summary>
    public TimeSpan? AccessTokenLifetime { get; init; }

    /// <summary>Whether a refresh token may be issued. Off for derived credentials (PAT exchanges).</summary>
    public bool AllowRefresh { get; init; } = true;

    /// <summary>When the session's absolute lifetime ends, for refresh-token lifetime; null for non-interactive grants.</summary>
    public DateTimeOffset? SessionEndsAt { get; init; }
}

/// <summary>
/// Stable error codes of grant refusals. The protocol layer answers <c>invalid_grant</c> with the code as an extra
/// parameter, so clients can tell "sign in with MFA" from "not allowed".
/// </summary>
public static class GrantErrors
{
    public const string InvalidGrant = "invalid_grant";
    public const string MfaRequired = "mfa_required";
    public const string AccountInactive = "account_inactive";
    public const string SessionExpired = "session_expired";
    public const string TenantInactive = "tenant_inactive";
    public const string NoMembership = "no_membership";
    public const string TokenInvalid = "token_invalid";
    public const string DirectoryUnavailable = "directory_unavailable";
}

using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Claims;

namespace JeffOps.Authentication.Abstractions.Access;

/// <summary>
/// Reads an <see cref="AccessContext"/> and related facts from a validated principal, using <see cref="ClaimNames"/>.
/// Pure and local; the ASP.NET Core accessors wrap it.
/// </summary>
public static class AccessContextReader
{
    /// <summary>
    /// The access context of <paramref name="user"/>. An unauthenticated principal yields <see cref="AccessContext.Anonymous"/>.
    /// A missing or unknown level reads as <see cref="AccessLevel.Tenant"/>.
    /// </summary>
    public static AccessContext Read(ClaimsPrincipal? user, ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(names);

        if (user?.Identity?.IsAuthenticated != true)
        {
            return AccessContext.Anonymous;
        }

        var level = Enum.TryParse<AccessLevel>(user.FindFirst(names.Level)?.Value, ignoreCase: true, out var parsed)
            && Enum.IsDefined(parsed)
                ? parsed
                : AccessLevel.Tenant;

        return new AccessContext(
            TenantId: GuidOf(user, names.Tenant),
            OrganizationId: GuidOf(user, names.Organization),
            WorkspaceId: GuidOf(user, names.Workspace),
            UserId: level == AccessLevel.Service ? null : GuidOf(user, names.Subject),
            Level: level,
            ActingTenantId: GuidOf(user, names.ActingTenant));
    }

    /// <summary>
    /// Whether <paramref name="user"/> is an interactive user rather than a service principal: the subject is a GUID and the
    /// level is not <see cref="AccessLevel.Service"/>.
    /// </summary>
    public static bool IsInteractiveUser(ClaimsPrincipal user, ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(names);

        return Guid.TryParse(user.FindFirst(names.Subject)?.Value, out _)
            && !string.Equals(user.FindFirst(names.Level)?.Value, nameof(AccessLevel.Service), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Whether <paramref name="user"/> carries any of the impersonation marker claims.</summary>
    public static bool IsImpersonation(ClaimsPrincipal user, ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(names);

        return user.Claims.Any(claim => names.IsImpersonationMarker(claim.Type));
    }

    /// <summary>
    /// Whether <paramref name="user"/>'s token was exchanged from a personal access token (<c>cred=pat</c>, or a PAT ceiling):
    /// a script's credential, never the user's own session.
    /// </summary>
    public static bool IsPatDerived(ClaimsPrincipal user, ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(names);

        return user.HasClaim(claim => (claim.Type == names.CredentialType && string.Equals(claim.Value, PatCredential, StringComparison.Ordinal))
            || claim.Type == names.PatCeiling);
    }

    /// <summary>
    /// Whether <paramref name="user"/> is in their own interactive session: an interactive user who isn't impersonating anyone,
    /// isn't switched into another tenant (no acting tenant, no delegation scope) and isn't using a token from a personal
    /// access token. Managing credentials, PATs, delegation consent and similar account actions need this.
    /// </summary>
    public static bool IsOwnSession(ClaimsPrincipal user, ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(names);

        return IsInteractiveUser(user, names)
            && !IsImpersonation(user, names)
            && !Read(user, names).IsDelegated
            && !user.HasClaim(claim => claim.Type == names.DelegationScope)
            && !IsPatDerived(user, names);
    }

    /// <summary>The <c>cred</c> value of tokens exchanged from a personal access token.</summary>
    public const string PatCredential = "pat";

    /// <summary>Whether the sign-in behind <paramref name="user"/> satisfied step-up.</summary>
    public static bool IsSteppedUp(ClaimsPrincipal user, ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(names);

        return user.HasClaim(claim => claim.Type == names.StepUp && string.Equals(claim.Value, names.StepUpSatisfied, StringComparison.Ordinal));
    }

    /// <summary>Every value of <paramref name="claimType"/>.</summary>
    public static IReadOnlyList<string> ValuesOf(ClaimsPrincipal user, string claimType)
    {
        ArgumentNullException.ThrowIfNull(user);
        return [.. user.FindAll(claimType).Select(claim => claim.Value)];
    }

    private static Guid? GuidOf(ClaimsPrincipal user, string claimType) =>
        Guid.TryParse(user.FindFirst(claimType)?.Value, out var value) ? value : null;
}

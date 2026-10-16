using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application.Features.PersonalAccessTokens;
using Microsoft.AspNetCore.Authorization;
using OpenIddict.Validation.AspNetCore;

namespace JeffOps.Authentication.Endpoints.Features;

/// <summary>Reads facts about the caller's own credential from its validated access token.</summary>
internal static class Callers
{
    /// <summary>Requires a valid access token issued by this server.</summary>
    public static AuthorizationPolicy TokenPolicy { get; } =
        new AuthorizationPolicyBuilder(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme).RequireAuthenticatedUser().Build();

    /// <summary>The caller as an interactive user, or null for a service principal or an unidentifiable token.</summary>
    public static PatCaller? AsUser(ClaimsPrincipal user, ClaimNames names)
    {
        if (!AccessContextReader.IsInteractiveUser(user, names) || !Guid.TryParse(user.FindFirst(names.Subject)?.Value, out var accountId))
        {
            return null;
        }

        var access = AccessContextReader.Read(user, names);
        return new PatCaller(
            accountId,
            access.TenantId,
            IsImpersonation: AccessContextReader.IsImpersonation(user, names),
            IsDelegated: access.IsDelegated || user.HasClaim(claim => claim.Type == names.DelegationScope),
            IsPatDerived: user.HasClaim(names.CredentialType, "pat") || user.HasClaim(claim => claim.Type == names.PatCeiling),
            IsSteppedUp: AccessContextReader.IsSteppedUp(user, names));
    }

    /// <summary>
    /// The account of a user acting as themselves: an interactive session that is not impersonating, not acting on a managed
    /// tenant and not derived from a personal access token. Null otherwise.
    /// </summary>
    public static Guid? OwnSessionAccount(ClaimsPrincipal user, ClaimNames names) =>
        AsUser(user, names) is { IsImpersonation: false, IsDelegated: false, IsPatDerived: false } caller ? caller.AccountId : null;

    /// <summary>
    /// Whether the caller is a service principal granted <paramref name="permission"/> (exact, <c>*</c>, or a <c>prefix.*</c>
    /// grant), as user lookups require (docs/DESIGN.md §17, I8).
    /// </summary>
    public static bool IsServiceWithPermission(ClaimsPrincipal user, ClaimNames names, string permission)
    {
        if (AccessContextReader.Read(user, names).Level != AccessLevel.Service)
        {
            return false;
        }

        return AccessContextReader.ValuesOf(user, names.ServicePermission).Any(held =>
            held == "*"
            || string.Equals(held, permission, StringComparison.OrdinalIgnoreCase)
            || (held.EndsWith(".*", StringComparison.Ordinal) && permission.StartsWith(held[..^1], StringComparison.OrdinalIgnoreCase)));
    }
}

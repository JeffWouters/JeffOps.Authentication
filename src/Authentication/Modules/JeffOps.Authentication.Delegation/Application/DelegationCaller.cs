using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Delegation.Application;

/// <summary>The user calling a delegation use case, read from their validated access token.</summary>
public sealed record DelegationCaller(Guid UserId, Guid? TenantId, Guid? OrganizationId, bool IsRoot, bool IsImpersonation, bool IsDelegated)
{
    /// <summary>Whether the caller is in their own session: not impersonating anyone and not switched into another tenant.</summary>
    public bool IsHomeSession => !IsImpersonation && !IsDelegated;

    /// <summary>The caller, or null for a service principal or an unidentifiable token.</summary>
    public static DelegationCaller? From(ClaimsPrincipal user, ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(names);

        if (!AccessContextReader.IsInteractiveUser(user, names) || !Guid.TryParse(user.FindFirst(names.Subject)?.Value, out var userId))
        {
            return null;
        }

        var access = AccessContextReader.Read(user, names);
        return new DelegationCaller(
            userId,
            access.TenantId,
            access.OrganizationId,
            access.IsRoot,
            AccessContextReader.IsImpersonation(user, names),
            access.IsDelegated || user.HasClaim(claim => claim.Type == names.DelegationScope));
    }
}

/// <summary>Stable error codes of delegation refusals.</summary>
public static class DelegationErrors
{
    public const string NotFound = "not_found";
    public const string NotAllowed = "not_allowed";
    public const string HomeSessionRequired = "home_session_required";
    public const string SelfImpersonation = "self_impersonation";
    public const string TargetInactive = "target_inactive";
    public const string NotManaged = "not_managed";
    public const string BreakGlassPlatformOnly = "break_glass_platform_only";
    public const string ReasonRequired = "reason_required";
    public const string Duplicate = "duplicate";
    public const string NotPending = "not_pending";
    public const string NotLive = "not_live";
    public const string ApprovalNotRequired = "approval_not_required";
    public const string OrganizationRequired = "organization_required";
    public const string Conflict = "conflict";
    public const string ActorRequired = "actor_required";
    public const string GrantInvalid = "grant_invalid";
    public const string Unavailable = "delegation_unavailable";
    public const string TargetProtected = "target_protected";
    public const string TenantApprovalRequired = "tenant_approval_required";
    public const string LevelTooLow = "level_too_low";

    public static Error HomeSession() =>
        Error.Forbidden(HomeSessionRequired, "Not available while impersonating or acting in another tenant.");

    public static Error Concurrent() =>
        Error.Conflict(Conflict, "The grant changed while this request ran. Reload and try again.");
}

using JeffOps.Authentication.Delegation.Domain;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Delegation.Application;

/// <summary>The lockbox rule, shared by tenant switch, delegated mints and partner impersonation.</summary>
internal static class Lockbox
{
    /// <summary>
    /// The live lockbox grant a partner needs for <paramref name="tenant"/> when the tenant requires approval; null when it
    /// doesn't; an error when it does and there is none. The same rule covers tenant switch and partner impersonation, so a
    /// lockbox can't be bypassed by impersonating one of the tenant's users.
    /// </summary>
    public static async Task<Result<TenantAccessGrant?>> GrantAsync(
        ITenantAccessGrantRepository grants, IDelegationDirectory directory, Guid actorId, Guid organization, Guid tenant, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var lockbox = await DirectoryCalls.RequiresApprovalAsync(directory, tenant, cancellationToken).ConfigureAwait(false);
        if (lockbox.IsFailure)
        {
            return lockbox.Error;
        }

        if (!lockbox.Value)
        {
            return Result.Success<TenantAccessGrant?>(null);
        }

        var open = await grants.ListOpenAsync(actorId, tenant, now, cancellationToken).ConfigureAwait(false);
        return open
            .Where(candidate => candidate.ActorUserId == actorId && candidate.TargetTenantId == tenant
                && candidate.ActorOrganizationId == organization && candidate.CanMint(now))
            .OrderByDescending(candidate => candidate.ApprovedAt)
            .FirstOrDefault() is { } grant
            ? grant
            : Error.Unauthorized(DelegationErrors.TenantApprovalRequired, "This tenant requires approval and there is no approved access grant.");
    }
}

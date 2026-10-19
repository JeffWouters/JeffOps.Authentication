using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Delegation.Application;

/// <summary>Rules on live tenant standing, shared by delegation requests and token mints.</summary>
internal static class ActorStanding
{
    /// <summary>Whether any of the account's memberships is Root. Platform administrators can't be impersonated.</summary>
    public static async Task<Result<bool>> IsPlatformAdministratorAsync(SessionBuilder sessions, Guid accountId, CancellationToken cancellationToken)
    {
        var memberships = await sessions.MembershipsAsync(accountId, cancellationToken).ConfigureAwait(false);
        return memberships.IsFailure
            ? memberships.Error
            : memberships.Value.Any(membership => membership.Level == AccessLevel.Root);
    }

    /// <summary>Acting in a customer's tenant is for the partner's own tenant members and above, not workspace guests.</summary>
    public static bool ReachesManagedTenants(TenantStanding standing) =>
        standing.Membership?.Level is AccessLevel.Tenant or AccessLevel.Organization or AccessLevel.Root;
}

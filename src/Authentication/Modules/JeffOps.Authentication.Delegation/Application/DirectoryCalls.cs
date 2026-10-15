using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Delegation.Application;

/// <summary>Directory calls that report an outage as <see cref="ErrorType.Unavailable"/>, so clients retry.</summary>
public static class DirectoryCalls
{
    public static async Task<Result<IReadOnlyList<string>>> ScopesAsync(IDelegationDirectory directory, Guid organization, Guid tenant, CancellationToken cancellationToken)
    {
        try
        {
            return Result.Success(await directory.GetDelegationScopesAsync(organization, tenant, cancellationToken).ConfigureAwait(false));
        }
#pragma warning disable CA1031 // A directory failure is an outage: clients retry instead of losing the session.
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
        {
            return Error.Unavailable(DelegationErrors.Unavailable, "The delegation directory is unavailable. Try again.");
        }
    }

    public static async Task<Result<bool>> RequiresApprovalAsync(IDelegationDirectory directory, Guid tenant, CancellationToken cancellationToken)
    {
        try
        {
            return await directory.RequiresAccessApprovalAsync(tenant, cancellationToken).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // See ScopesAsync.
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
        {
            return Error.Unavailable(DelegationErrors.Unavailable, "The delegation directory is unavailable. Try again.");
        }
    }

    public static async Task<Result<TenantInfo?>> TenantAsync(ITenantDirectory tenants, Guid tenant, CancellationToken cancellationToken)
    {
        try
        {
            return Result.Success(await tenants.FindTenantAsync(tenant, cancellationToken).ConfigureAwait(false));
        }
#pragma warning disable CA1031 // See ScopesAsync.
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
        {
            return Error.Unavailable(GrantErrors.DirectoryUnavailable, "The tenant directory is unavailable. Try again.");
        }
    }
}

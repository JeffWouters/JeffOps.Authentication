using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Delegation.Application;
using JeffOps.Authentication.Delegation.Domain;
using Microsoft.EntityFrameworkCore;

namespace JeffOps.Authentication.Delegation.Infrastructure;

/// <summary>
/// Grants a deleted account takes part in, as the actor or the impersonated user, end (pending or live); finished grants stay,
/// as the audit trail of who acted as whom.
/// </summary>
internal sealed class DelegationAccountData(DelegationDbContext db, IDelegationUnitOfWork unitOfWork, TimeProvider time) : IAccountDataEraser
{
    private static readonly DelegationGrantStatus[] Open = [DelegationGrantStatus.PendingApproval, DelegationGrantStatus.Approved, DelegationGrantStatus.Active];

    public Task<AccountDeletionBlocker?> BlockerAsync(Guid accountId, CancellationToken cancellationToken) =>
        Task.FromResult<AccountDeletionBlocker?>(null);

    public async Task EraseAsync(Guid accountId, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var impersonations = await db.ImpersonationGrants
            .Where(grant => Open.Contains(grant.Status) && (grant.ActorUserId == accountId || grant.TargetUserId == accountId))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var tenantAccess = await db.TenantAccessGrants
            .Where(grant => Open.Contains(grant.Status) && grant.ActorUserId == accountId)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        if (impersonations.Count + tenantAccess.Count == 0)
        {
            return;
        }

        foreach (var grant in impersonations.Cast<DelegationGrant>().Concat(tenantAccess))
        {
            grant.Revoke(now, GrantEndReasons.AccountDeleted);
        }

        if (!await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException("A grant of the account changed while it was being deleted; delete it again.");
        }
    }
}

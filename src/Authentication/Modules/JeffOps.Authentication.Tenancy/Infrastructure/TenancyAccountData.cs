using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Tenancy.Domain;
using Microsoft.EntityFrameworkCore;

namespace JeffOps.Authentication.Tenancy.Infrastructure;

/// <summary>
/// A deleted account's memberships. The only administrator of a tenant that isn't deleted can't be deleted (the tenant
/// would have no one to run it); who created or invited what stays recorded, by account id.
/// </summary>
internal sealed class TenancyAccountData(TenancyDbContext db) : IAccountDataEraser
{
    public const string LastTenantAdmin = "last_tenant_admin";

    public async Task<AccountDeletionBlocker?> BlockerAsync(Guid accountId, CancellationToken cancellationToken)
    {
        var administered = db.Memberships.Where(membership => membership.AccountId == accountId && membership.Role == MembershipRole.Admin)
            .Select(membership => membership.TenantId);
        var alone = await db.Tenants
            .Where(tenant => administered.Contains(tenant.Id)
                && tenant.Status != TenantStatus.Deleted
                && !db.Memberships.Any(other => other.TenantId == tenant.Id && other.Role == MembershipRole.Admin && other.AccountId != accountId))
            .Select(tenant => tenant.Name)
            .FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);

        return alone is null
            ? null
            : new AccountDeletionBlocker(LastTenantAdmin, $"This account is the only administrator of {alone}. Make someone else an administrator first.");
    }

    public Task EraseAsync(Guid accountId, CancellationToken cancellationToken) =>
        db.Memberships.Where(membership => membership.AccountId == accountId).ExecuteDeleteAsync(cancellationToken);
}

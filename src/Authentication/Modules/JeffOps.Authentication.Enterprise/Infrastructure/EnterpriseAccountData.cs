using JeffOps.Authentication.Application.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace JeffOps.Authentication.Enterprise.Infrastructure;

/// <summary>
/// An account an organization provisions (SCIM) is the organization's to remove, through its identity provider: it can't be
/// deleted here. Otherwise the account leaves the SCIM groups it is still in.
/// </summary>
internal sealed class EnterpriseAccountData(EnterpriseDbContext db, TimeProvider time) : IAccountDataEraser
{
    public const string ManagedByOrganization = "managed_by_organization";

    public async Task<AccountDeletionBlocker?> BlockerAsync(Guid accountId, CancellationToken cancellationToken) =>
        await db.ScimUsers.AnyAsync(user => user.AccountId == accountId, cancellationToken).ConfigureAwait(false)
            ? new AccountDeletionBlocker(ManagedByOrganization, "Your organization manages this account. Ask its administrator to remove it.")
            : null;

    public async Task EraseAsync(Guid accountId, CancellationToken cancellationToken)
    {
        var groups = await db.ScimGroups.Where(group => group.Members.Any(member => member.AccountId == accountId)).ToListAsync(cancellationToken).ConfigureAwait(false);
        foreach (var group in groups)
        {
            group.RemoveMembers([accountId], time.GetUtcNow());
        }

        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}

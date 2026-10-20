using JeffOps.Authentication.Application.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace JeffOps.Authentication.LocalAccounts.Infrastructure;

/// <summary>A deleted account's password, authenticator, passkeys, recovery codes and pending email links.</summary>
internal sealed class LocalAccountData(LocalAccountsDbContext db) : IAccountDataEraser
{
    public Task<AccountDeletionBlocker?> BlockerAsync(Guid accountId, CancellationToken cancellationToken) =>
        Task.FromResult<AccountDeletionBlocker?>(null);

    public async Task EraseAsync(Guid accountId, CancellationToken cancellationToken)
    {
        // Loaded (its id is the account's), so its passkeys and recovery codes go with it.
        db.Credentials.RemoveRange(await db.Credentials.Where(credential => credential.Id == accountId).ToListAsync(cancellationToken).ConfigureAwait(false));
        db.Tokens.RemoveRange(await db.Tokens.Where(token => token.AccountId == accountId).ToListAsync(cancellationToken).ConfigureAwait(false));
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}

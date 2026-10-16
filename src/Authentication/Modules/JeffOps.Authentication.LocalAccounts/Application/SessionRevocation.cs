using JeffOps.Authentication.Application.Abstractions;

namespace JeffOps.Authentication.LocalAccounts.Application;

/// <summary>
/// Ends every session of an account after a credential changed or was removed, so a session opened with the old credential
/// (possibly by an attacker) doesn't outlive the change.
/// </summary>
public sealed class CredentialChangeSessions(IAccountRepository accounts, IUnitOfWork unitOfWork, TimeProvider time)
{
    public async Task RevokeAsync(Guid accountId, string reason, CancellationToken cancellationToken)
    {
        if (await accounts.FindAsync(accountId, cancellationToken).ConfigureAwait(false) is { } account)
        {
            account.RevokeSessions(time.GetUtcNow(), reason);
            await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}

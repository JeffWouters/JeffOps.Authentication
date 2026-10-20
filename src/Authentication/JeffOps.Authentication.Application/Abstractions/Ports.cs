using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.PersonalAccessTokens;

namespace JeffOps.Authentication.Application.Abstractions;

/// <summary>Accounts storage.</summary>
public interface IAccountRepository
{
    Task<Account?> FindAsync(Guid accountId, CancellationToken cancellationToken);

    /// <summary>The oldest account with this (normalized) email. Emails are not unique; use only for lookups, never for linking.</summary>
    Task<Account?> FindByEmailAsync(string email, CancellationToken cancellationToken);

    /// <summary>The ids of every account with this (normalized) email, oldest first (no accounts loaded).</summary>
    Task<IReadOnlyList<Guid>> FindIdsByEmailAsync(string email, CancellationToken cancellationToken);

    Task<Account?> FindByExternalLoginAsync(ExternalLoginKey login, CancellationToken cancellationToken);

    /// <summary>The emails of the accounts among <paramref name="accountIds"/> that exist, in one read (no accounts loaded).</summary>
    Task<IReadOnlyDictionary<Guid, string>> FindEmailsAsync(IReadOnlyCollection<Guid> accountIds, CancellationToken cancellationToken);

    /// <summary>
    /// Accounts inactive since <paramref name="inactiveSince"/> (<see cref="Account.LastActiveAt"/>) whose user wasn't told of
    /// their deletion yet, longest inactive first, at most <paramref name="max"/>.
    /// </summary>
    Task<IReadOnlyList<Account>> ListToWarnOfDeletionAsync(DateTimeOffset inactiveSince, int max, CancellationToken cancellationToken);

    /// <summary>Accounts still inactive since <paramref name="inactiveSince"/> whose user was told before <paramref name="warnedBefore"/>.</summary>
    Task<IReadOnlyList<Account>> ListDueForDeletionAsync(DateTimeOffset inactiveSince, DateTimeOffset warnedBefore, int max, CancellationToken cancellationToken);

    void Add(Account account);

    void Remove(Account account);
}

/// <summary>Why an account can't be deleted now, for example the only administrator of a tenant.</summary>
/// <param name="Code">A stable code, such as <c>last_tenant_admin</c>.</param>
/// <param name="Message">For the user.</param>
public sealed record AccountDeletionBlocker(string Code, string Message);

/// <summary>
/// What a module keeps about an account, removed when the account is deleted. Each module with data per account registers
/// one, and so do the token server's own tables. Deletion asks every one for a blocker first, then erases with every one, then
/// deletes the account: a deletion that failed half-way leaves the account, and runs again.
/// </summary>
public interface IAccountDataEraser
{
    /// <summary>Why the account can't be deleted now, or null.</summary>
    Task<AccountDeletionBlocker?> BlockerAsync(Guid accountId, CancellationToken cancellationToken);

    /// <summary>Removes what this module keeps about the account. Safe to repeat.</summary>
    Task EraseAsync(Guid accountId, CancellationToken cancellationToken);
}

/// <summary>Personal access token storage.</summary>
public interface IPersonalAccessTokenRepository
{
    Task<PersonalAccessToken?> FindBySecretHashAsync(string secretHash, CancellationToken cancellationToken);

    Task<PersonalAccessToken?> FindAsync(Guid tokenId, Guid accountId, CancellationToken cancellationToken);

    Task<IReadOnlyList<PersonalAccessToken>> ListForAccountAsync(Guid accountId, CancellationToken cancellationToken);

    void Add(PersonalAccessToken token);
}

/// <summary>Commits the changes of one use case atomically and then dispatches the domain events they raised.</summary>
/// <summary>Sign-in sessions ended by signing out at the token server, kept until their tokens can no longer be refreshed.</summary>
public interface IEndedSessions
{
    Task<bool> IsEndedAsync(string sessionId, CancellationToken cancellationToken);

    Task EndAsync(string sessionId, Guid accountId, DateTimeOffset now, CancellationToken cancellationToken);
}

/// <summary>Tells clients that one sign-in session ended (OpenID Connect Back-Channel Logout with <c>sid</c>).</summary>
public interface ISessionLogoutNotifier
{
    Task SessionEndedAsync(Guid accountId, string sessionId, CancellationToken cancellationToken);
}

public interface IUnitOfWork
{
    Task SaveChangesAsync(CancellationToken cancellationToken);
}

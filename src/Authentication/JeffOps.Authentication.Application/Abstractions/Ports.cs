using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.PersonalAccessTokens;

namespace JeffOps.Authentication.Application.Abstractions;

/// <summary>Accounts storage.</summary>
public interface IAccountRepository
{
    Task<Account?> FindAsync(Guid accountId, CancellationToken cancellationToken);

    /// <summary>The oldest account with this (normalized) email. Emails are not unique; use only for lookups, never for linking.</summary>
    Task<Account?> FindByEmailAsync(string email, CancellationToken cancellationToken);

    Task<Account?> FindByExternalLoginAsync(ExternalLoginKey login, CancellationToken cancellationToken);

    void Add(Account account);
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

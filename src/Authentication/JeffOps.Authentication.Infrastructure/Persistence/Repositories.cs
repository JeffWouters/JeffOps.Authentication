using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.PersonalAccessTokens;
using JeffOps.Authentication.SharedKernel.Domain;
using Microsoft.EntityFrameworkCore;

namespace JeffOps.Authentication.Infrastructure.Persistence;

internal sealed class AccountRepository(AuthenticationDbContext db) : IAccountRepository
{
    public Task<Account?> FindAsync(Guid accountId, CancellationToken cancellationToken) =>
        db.Accounts.FirstOrDefaultAsync(account => account.Id == accountId, cancellationToken);

    public async Task<Account?> FindByEmailAsync(string email, CancellationToken cancellationToken)
    {
        // Ordered in memory: DateTimeOffset ordering isn't translatable on every provider, and the match set is tiny.
        var normalized = Account.NormalizeEmail(email ?? string.Empty);
        var matches = await db.Accounts.Where(account => account.Email == normalized).ToListAsync(cancellationToken).ConfigureAwait(false);
        return matches.OrderBy(account => account.CreatedAt).FirstOrDefault();
    }

    public async Task<IReadOnlyList<Guid>> FindIdsByEmailAsync(string email, CancellationToken cancellationToken)
    {
        var normalized = Account.NormalizeEmail(email ?? string.Empty);
        var matches = await db.Accounts.Where(account => account.Email == normalized)
            .Select(account => new { account.Id, account.CreatedAt })
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return [.. matches.OrderBy(account => account.CreatedAt).Select(account => account.Id)];
    }

    public async Task<Account?> FindByExternalLoginAsync(ExternalLoginKey login, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(login);

        var accountId = await db.ExternalLogins
            .Where(link => link.Issuer == login.Issuer && link.Subject == login.Subject)
            .Select(link => (Guid?)link.AccountId)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);

        return accountId is { } id ? await FindAsync(id, cancellationToken).ConfigureAwait(false) : null;
    }

    public async Task<IReadOnlyDictionary<Guid, string>> FindEmailsAsync(IReadOnlyCollection<Guid> accountIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accountIds);
        return accountIds.Count == 0
            ? new Dictionary<Guid, string>()
            : await db.Accounts.Where(account => accountIds.Contains(account.Id))
                .Select(account => new { account.Id, account.Email })
                .ToDictionaryAsync(account => account.Id, account => account.Email, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<Account>> ListToWarnOfDeletionAsync(DateTimeOffset inactiveSince, int max, CancellationToken cancellationToken) =>
        await db.Accounts
            .Where(account => account.DeletionWarnedAt == null && account.LastActiveAt <= inactiveSince)
            .OrderBy(account => account.LastActiveAt)
            .Take(max)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<Account>> ListDueForDeletionAsync(DateTimeOffset inactiveSince, DateTimeOffset warnedBefore, int max, CancellationToken cancellationToken) =>
        await db.Accounts
            .Where(account => account.DeletionWarnedAt != null && account.DeletionWarnedAt <= warnedBefore && account.LastActiveAt <= inactiveSince)
            .OrderBy(account => account.DeletionWarnedAt)
            .Take(max)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(Account account) => db.Accounts.Add(account);

    public void Remove(Account account) => db.Accounts.Remove(account);
}

internal sealed class PersonalAccessTokenRepository(AuthenticationDbContext db) : IPersonalAccessTokenRepository
{
    public Task<PersonalAccessToken?> FindBySecretHashAsync(string secretHash, CancellationToken cancellationToken) =>
        db.PersonalAccessTokens.FirstOrDefaultAsync(token => token.SecretHash == secretHash, cancellationToken);

    public Task<PersonalAccessToken?> FindAsync(Guid tokenId, Guid accountId, CancellationToken cancellationToken) =>
        db.PersonalAccessTokens.FirstOrDefaultAsync(token => token.Id == tokenId && token.AccountId == accountId, cancellationToken);

    public async Task<IReadOnlyList<PersonalAccessToken>> ListForAccountAsync(Guid accountId, CancellationToken cancellationToken) =>
        await db.PersonalAccessTokens.Where(token => token.AccountId == accountId).ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(PersonalAccessToken token) => db.PersonalAccessTokens.Add(token);
}

/// <summary>Saves, then dispatches the domain events raised by the saved aggregates.</summary>
internal sealed class EfUnitOfWork(AuthenticationDbContext db, IDomainEventDispatcher dispatcher) : IUnitOfWork
{
    public async Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        var aggregates = db.ChangeTracker.Entries<IHasDomainEvents>()
            .Select(entry => entry.Entity)
            .Where(entity => entity.DomainEvents.Count > 0)
            .ToList();
        var events = aggregates.SelectMany(aggregate => aggregate.DomainEvents).ToList();

        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        foreach (var aggregate in aggregates)
        {
            aggregate.ClearDomainEvents();
        }

        await dispatcher.DispatchAsync(events, cancellationToken).ConfigureAwait(false);
    }
}

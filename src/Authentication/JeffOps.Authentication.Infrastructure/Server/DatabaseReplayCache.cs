using JeffOps.Authentication.Abstractions.Replay;
using JeffOps.Authentication.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>A one-time value the token server has seen, kept until it could no longer be accepted.</summary>
public sealed class ReplayEntry
{
    /// <summary>Records <paramref name="key"/> until <paramref name="expiresAtUnixMs"/>.</summary>
    public ReplayEntry(string key, long expiresAtUnixMs)
    {
        Key = key;
        ExpiresAtUnixMs = expiresAtUnixMs;
    }

    private ReplayEntry()
    {
    }

    /// <summary>The value's key (<see cref="ReplayKeys"/>): a purpose and a hash, never the value itself.</summary>
    public string Key { get; private set; } = string.Empty;

    /// <summary>When the entry may go, in Unix milliseconds (compares the same in every database).</summary>
    public long ExpiresAtUnixMs { get; private set; }
}

/// <summary>
/// The token server's <see cref="IReplayCache"/>: the database's primary key makes check-and-record atomic across every
/// instance, so a DPoP proof or SAML assertion counts once however many replicas run. Uses its own short-lived context, so it
/// never saves a request's other changes. Expired entries are pruned at most once a minute per instance.
/// </summary>
internal sealed class DatabaseReplayCache(IServiceScopeFactory scopes, TimeProvider time) : IReplayCache
{
    private long _nextPrune;

    public async ValueTask<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(key);
        var now = time.GetUtcNow().ToUnixTimeMilliseconds();
        var expires = expiresAt.ToUnixTimeMilliseconds();

        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>();

        if (now >= Interlocked.Read(ref _nextPrune))
        {
            Interlocked.Exchange(ref _nextPrune, now + 60_000);
            await db.ReplayEntries.Where(entry => entry.ExpiresAtUnixMs <= now).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        }

        // The common case, a value not seen before, is one insert; the primary key makes it atomic across instances.
        db.ReplayEntries.Add(new ReplayEntry(key, expires));
        try
        {
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (DbUpdateException)
        {
            db.ChangeTracker.Clear();
        }

        // The key is there: a replay, unless its entry has expired, when it is taken over. The update matches one row at most,
        // so of two requests taking over the same expired key, one wins.
        try
        {
            return await db.ReplayEntries
                .Where(entry => entry.Key == key && entry.ExpiresAtUnixMs <= now)
                .ExecuteUpdateAsync(set => set.SetProperty(entry => entry.ExpiresAtUnixMs, expires), cancellationToken)
                .ConfigureAwait(false) == 1;
        }
        catch (System.Data.Common.DbException)
        {
            // The database refused the write: don't accept the value.
            return false;
        }
    }
}

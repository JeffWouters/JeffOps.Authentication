using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>A sign-in session the user ended by signing out at the token server.</summary>
public sealed class EndedSession
{
    /// <summary>Records that <paramref name="sessionId"/> of <paramref name="accountId"/> ended at <paramref name="endedAtUnixMs"/>.</summary>
    public EndedSession(string sessionId, Guid accountId, long endedAtUnixMs)
    {
        SessionId = sessionId;
        AccountId = accountId;
        EndedAtUnixMs = endedAtUnixMs;
    }

    private EndedSession()
    {
    }

    /// <summary>The session (<c>sid</c>).</summary>
    public string SessionId { get; private set; } = string.Empty;

    /// <summary>Whose session it was.</summary>
    public Guid AccountId { get; private set; }

    /// <summary>When it ended, in Unix milliseconds (compares the same in every database).</summary>
    public long EndedAtUnixMs { get; private set; }
}

/// <summary>
/// Ended sessions in the token server's database. An entry is needed only while the session's tokens could still be
/// refreshed, so entries older than the session lifetime are pruned.
/// </summary>
internal sealed class DatabaseEndedSessions(AuthenticationDbContext db, IOptions<TokenServerOptions> options, TimeProvider time) : IEndedSessions
{
    public Task<bool> IsEndedAsync(string sessionId, CancellationToken cancellationToken) =>
        db.EndedSessions.AnyAsync(session => session.SessionId == sessionId, cancellationToken);

    public async Task EndAsync(string sessionId, Guid accountId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionId);
        var cutoff = (time.GetUtcNow() - options.Value.SessionLifetime).ToUnixTimeMilliseconds();
        await db.EndedSessions.Where(session => session.EndedAtUnixMs < cutoff).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);

        if (await db.EndedSessions.AnyAsync(session => session.SessionId == sessionId, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        db.EndedSessions.Add(new EndedSession(sessionId, accountId, now.ToUnixTimeMilliseconds()));
        try
        {
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateException)
        {
            // Ended at the same moment by another request: it's ended either way.
        }
    }
}

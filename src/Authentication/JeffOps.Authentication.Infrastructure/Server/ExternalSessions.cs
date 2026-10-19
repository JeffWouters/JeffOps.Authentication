using System.Security.Cryptography;
using System.Text;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>A session here that a sign-in through an external provider started, with the provider's own session.</summary>
public sealed class ExternalSessionEntry
{
    /// <summary>Records <paramref name="sessionId"/> of <paramref name="accountId"/>, from <paramref name="provider"/>'s session (hashed).</summary>
    public ExternalSessionEntry(string sessionId, string provider, string? providerSessionHash, Guid accountId, long expiresAtUnixMs)
    {
        SessionId = sessionId;
        Provider = provider;
        ProviderSessionHash = providerSessionHash;
        AccountId = accountId;
        ExpiresAtUnixMs = expiresAtUnixMs;
    }

    private ExternalSessionEntry()
    {
    }

    /// <summary>The session here (<c>sid</c>).</summary>
    public string SessionId { get; private set; } = string.Empty;

    /// <summary>The provider's name.</summary>
    public string Provider { get; private set; } = string.Empty;

    /// <summary>The SHA-256 (hex) of the provider's session id, when it gave one.</summary>
    public string? ProviderSessionHash { get; private set; }

    /// <summary>Whose session it is.</summary>
    public Guid AccountId { get; private set; }

    /// <summary>When the session here can no longer be alive, in Unix milliseconds.</summary>
    public long ExpiresAtUnixMs { get; private set; }
}

/// <summary>External sessions in the token server's database; expired entries are ignored, and pruned by <see cref="StoreMaintenance"/>.</summary>
internal sealed class DatabaseExternalSessions(AuthenticationDbContext db, TimeProvider time) : IExternalSessions
{
    public async Task RecordAsync(string provider, string? providerSessionId, Guid accountId, string sessionId, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(provider);
        ArgumentException.ThrowIfNullOrEmpty(sessionId);
        db.ExternalSessions.Add(new ExternalSessionEntry(sessionId, provider, Hash(providerSessionId), accountId, expiresAt.ToUnixTimeMilliseconds()));
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<ExternalSession>> FindAsync(string provider, string? providerSessionId, Guid? accountId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(provider);
        if (providerSessionId is null && accountId is null)
        {
            return [];
        }

        var now = time.GetUtcNow().ToUnixTimeMilliseconds();
        var query = db.ExternalSessions.Where(entry => entry.Provider == provider && entry.ExpiresAtUnixMs > now);
        if (Hash(providerSessionId) is { } hash)
        {
            query = query.Where(entry => entry.ProviderSessionHash == hash);
        }

        if (accountId is { } account)
        {
            query = query.Where(entry => entry.AccountId == account);
        }

        return await query.Select(entry => new ExternalSession(entry.AccountId, entry.SessionId)).ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task RemoveAsync(IReadOnlyCollection<string> sessionIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sessionIds);
        if (sessionIds.Count > 0)
        {
            await db.ExternalSessions.Where(entry => sessionIds.Contains(entry.SessionId)).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private static string? Hash(string? providerSessionId) =>
        string.IsNullOrEmpty(providerSessionId) ? null : Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(providerSessionId)));
}

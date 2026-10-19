using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Bff.Sessions;

/// <summary>A browser session: the tokens the BFF holds on the browser's behalf.</summary>
/// <param name="Subject">The user (<c>sub</c>); for a derived session, the user of the own session it belongs to.</param>
/// <param name="AccessToken">The current access token.</param>
/// <param name="RefreshToken">The current refresh token.</param>
/// <param name="IdentityToken">The ID token, kept for the end-session request.</param>
/// <param name="AccessExpiresAt">When the access token expires.</param>
/// <param name="SessionEndsAt">The session's absolute deadline, fixed at sign-in.</param>
public sealed record BffSession(
    string Subject,
    string AccessToken,
    string? RefreshToken,
    string? IdentityToken,
    DateTimeOffset AccessExpiresAt,
    DateTimeOffset SessionEndsAt)
{
    /// <summary>
    /// The access token for the token server's own APIs (audience: the token server only), when one was fetched; never sent
    /// to APIs (<see cref="BffOptions.AccountApi"/>).
    /// </summary>
    public string? AccountAccessToken { get; init; }

    /// <summary>When <see cref="AccountAccessToken"/> expires.</summary>
    public DateTimeOffset? AccountAccessExpiresAt { get; init; }

    /// <summary>For a derived session: <c>impersonation</c> or <c>tenant-switch</c>; null for an own session.</summary>
    public string? Kind { get; init; }

    /// <summary>For a derived session: <see cref="BffSessionStore.KeyFor"/> of the own session it belongs to.</summary>
    public string? OwnerKey { get; init; }

    /// <summary>For impersonation: the grant minted against.</summary>
    public string? GrantId { get; init; }

    /// <summary>For tenant switch: the tenant acted in.</summary>
    public string? ActingTenantId { get; init; }

    /// <summary>Whether this is a derived (impersonation or tenant-switch) session rather than an own session.</summary>
    public bool IsDerived => Kind is not null;
}

/// <summary>The session store could not be reached; the request is answered 503 rather than treated as signed out.</summary>
public sealed class SessionStoreUnavailableException : Exception
{
    /// <summary>Creates the exception with a default message.</summary>
    public SessionStoreUnavailableException()
        : base("The session store is unavailable.")
    {
    }

    /// <summary>Creates the exception with <paramref name="message"/>.</summary>
    public SessionStoreUnavailableException(string message)
        : base(message)
    {
    }

    /// <summary>Creates the exception with <paramref name="message"/> and the store failure behind it.</summary>
    public SessionStoreUnavailableException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Stores sessions in <see cref="IDistributedCache"/> (Redis in production). The session id in the cookie is 256 random bits;
/// the cache key is its SHA-256, so a cache reader can't recover cookies; the value is encrypted with Data Protection, so
/// tokens never sit in clear in the cache. Every entry expires at the session's absolute deadline and after the idle timeout.
/// A per-user index lets a back-channel logout end all of a user's sessions.
/// </summary>
public sealed class BffSessionStore(IDistributedCache cache, IDataProtectionProvider dataProtection, IOptions<BffOptions> options, TimeProvider time)
{
    private const string SessionPrefix = "jeffops:bff:sid:";
    private const string SubjectPrefix = "jeffops:bff:sub:";

    private readonly IDataProtector _protector = dataProtection.CreateProtector("JeffOps.Bff.Session");

    /// <summary>A new session id: 256 random bits as lowercase hex. It goes in the cookie; the store keys on its hash.</summary>
    public static string NewId() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));

    /// <summary>The store key of a session id: what a derived session records as its owner, never the id itself.</summary>
    public static string KeyFor(string id) => KeyOf(id);

    /// <summary>Stores a new session and indexes it under its subject; returns the session id for the cookie.</summary>
    public async Task<string> CreateAsync(BffSession session, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        var id = NewId();
        await WriteAsync(id, session, cancellationToken).ConfigureAwait(false);
        await IndexAsync(session.Subject, add: KeyOf(id), remove: null, cancellationToken).ConfigureAwait(false);
        return id;
    }

    /// <summary>Overwrites session <paramref name="id"/>, for example after a token refresh.</summary>
    public Task UpdateAsync(string id, BffSession session, CancellationToken cancellationToken) => WriteAsync(id, session, cancellationToken);

    /// <summary>
    /// Session <paramref name="id"/>, or null when it is missing, past its deadline or can't be decrypted. Throws
    /// <see cref="SessionStoreUnavailableException"/> when the store can't be reached.
    /// </summary>
    public Task<BffSession?> GetAsync(string id, CancellationToken cancellationToken) => ReadSessionAsync(KeyOf(id), cancellationToken);

    private async Task<BffSession?> ReadSessionAsync(string key, CancellationToken cancellationToken)
    {
        var blob = await ReadAsync(key, cancellationToken).ConfigureAwait(false);
        if (blob is null)
        {
            return null;
        }

        BffSession? session;
        try
        {
            session = JsonSerializer.Deserialize<BffSession>(_protector.Unprotect(blob));
        }
        catch (CryptographicException)
        {
            return null; // tampered with, or protected under a key ring that is gone
        }
        catch (JsonException)
        {
            return null;
        }

        return session is not null && session.SessionEndsAt > time.GetUtcNow() ? session : null;
    }

    /// <summary>Deletes session <paramref name="id"/>; with <paramref name="subject"/>, also removes it from that user's index.</summary>
    public async Task DeleteAsync(string id, string? subject, CancellationToken cancellationToken)
    {
        await RemoveAsync(KeyOf(id), cancellationToken).ConfigureAwait(false);
        if (subject is not null)
        {
            await IndexAsync(subject, add: null, remove: KeyOf(id), cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Ends every session of <paramref name="subject"/> (back-channel logout).</summary>
    public async Task<int> DeleteAllAsync(string subject, CancellationToken cancellationToken)
    {
        var keys = await SessionKeysAsync(subject, cancellationToken).ConfigureAwait(false);
        foreach (var key in keys)
        {
            await RemoveAsync(key, cancellationToken).ConfigureAwait(false);
        }

        await RemoveAsync(SubjectKeyOf(subject), cancellationToken).ConfigureAwait(false);
        return keys.Count;
    }

    /// <summary>
    /// Ends the sessions of <paramref name="subject"/> that belong to the token server's session <paramref name="sessionId"/>
    /// (back-channel logout naming one session, <c>sid</c>), with the impersonation and tenant-switch sessions derived from
    /// them. The user's other sessions continue.
    /// </summary>
    public async Task<int> DeleteSessionAsync(string subject, string sessionId, CancellationToken cancellationToken)
    {
        var keys = await SessionKeysAsync(subject, cancellationToken).ConfigureAwait(false);
        var sessions = new Dictionary<string, BffSession>(StringComparer.Ordinal);
        foreach (var key in keys)
        {
            if (await ReadSessionAsync(key, cancellationToken).ConfigureAwait(false) is { } session)
            {
                sessions[key] = session;
            }
        }

        var ending = sessions.Where(pair => string.Equals(SessionIdOf(pair.Value.IdentityToken), sessionId, StringComparison.Ordinal))
            .Select(pair => pair.Key).ToHashSet(StringComparer.Ordinal);
        ending.UnionWith(sessions.Where(pair => pair.Value.OwnerKey is { } owner && ending.Contains(owner)).Select(pair => pair.Key));

        foreach (var key in ending)
        {
            await RemoveAsync(key, cancellationToken).ConfigureAwait(false);
            await IndexAsync(subject, add: null, remove: key, cancellationToken).ConfigureAwait(false);
        }

        return ending.Count;
    }

    /// <summary>The token server session (<c>sid</c>) of a stored, already validated ID token.</summary>
    private static string? SessionIdOf(string? identityToken)
    {
        if (string.IsNullOrEmpty(identityToken))
        {
            return null;
        }

        try
        {
            return new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(identityToken).TryGetPayloadValue<string>("sid", out var sid) ? sid : null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private async Task WriteAsync(string id, BffSession session, CancellationToken cancellationToken)
    {
        var remaining = session.SessionEndsAt - time.GetUtcNow();
        if (remaining <= TimeSpan.Zero)
        {
            await RemoveAsync(KeyOf(id), cancellationToken).ConfigureAwait(false);
            return;
        }

        var idle = options.Value.IdleTimeout;
        try
        {
            await cache.SetStringAsync(
                KeyOf(id),
                _protector.Protect(JsonSerializer.Serialize(session)),
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = remaining,
                    SlidingExpiration = idle < remaining ? idle : remaining,
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new SessionStoreUnavailableException("The session could not be saved.", exception);
        }
    }

    private async Task IndexAsync(string subject, string? add, string? remove, CancellationToken cancellationToken)
    {
        // Best effort under concurrency: the index only speeds up back-channel logout; each session still expires on its own.
        var keys = await SessionKeysAsync(subject, cancellationToken).ConfigureAwait(false);
        if (add is not null)
        {
            keys.Add(add);
        }

        if (remove is not null)
        {
            keys.Remove(remove);
        }

        try
        {
            await cache.SetStringAsync(
                SubjectKeyOf(subject),
                JsonSerializer.Serialize(keys),
                new DistributedCacheEntryOptions { AbsoluteExpirationRelativeToNow = options.Value.SessionLifetime },
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new SessionStoreUnavailableException("The session index could not be saved.", exception);
        }
    }

    private async Task<HashSet<string>> SessionKeysAsync(string subject, CancellationToken cancellationToken)
    {
        var json = await ReadAsync(SubjectKeyOf(subject), cancellationToken).ConfigureAwait(false);
        return json is null ? [] : JsonSerializer.Deserialize<HashSet<string>>(json) ?? [];
    }

    private async Task<string?> ReadAsync(string key, CancellationToken cancellationToken)
    {
        try
        {
            return await cache.GetStringAsync(key, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new SessionStoreUnavailableException("The session store could not be read.", exception);
        }
    }

    private async Task RemoveAsync(string key, CancellationToken cancellationToken)
    {
        try
        {
            await cache.RemoveAsync(key, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            throw new SessionStoreUnavailableException("The session could not be removed.", exception);
        }
    }

    private static string KeyOf(string id) => SessionPrefix + Hash(id);

    private static string SubjectKeyOf(string subject) => SubjectPrefix + Hash(subject);

    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

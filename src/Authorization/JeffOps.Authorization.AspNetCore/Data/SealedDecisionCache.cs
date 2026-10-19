using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Hybrid;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JeffOps.Authorization.AspNetCore.Data;

/// <summary>
/// A decision-cache value as stored: the JSON payload, the id of the key that sealed it, the time it stops being accepted,
/// the time it was sealed, and an HMAC over the storage key, those times and the payload. Immutable, so the local cache
/// hands back the same instance and a verified value is memoised per instance.
/// </summary>
[ImmutableObject(true)]
internal sealed record SealedCacheEntry(string Kid, string Payload, string Mac, long ExpiresAtUnixMs, long SealedAtUnixMs = 0);

/// <summary>
/// Integrity protection for the authorization decision caches. A distributed cache is often shared by many workloads with
/// one credential; plain JSON under predictable keys would let any of them plant "this user is an owner here". Each value is
/// sealed with HMAC-SHA256 under this service's key and bound to its storage key and an expiry, so a forged entry or a
/// genuine entry copied under another key is rejected, evicted and re-read from the source. A genuine entry put back after
/// an invalidation event this process handled is rejected too (it was sealed before the invalidation); without invalidation
/// events, a genuine entry stays acceptable until its lifetime plus <see cref="DecisionCacheOptions.MaxStale"/> ends.
/// </summary>
internal sealed partial class SealedDecisionCache
{
    /// <summary>The shortest sealing key accepted outside Development: 32 bytes, the HMAC-SHA256 block of entropy.</summary>
    public const int MinimumSealingKeyBytes = 32;

    private const int InvalidationsBeforePruning = 10_000;

    private readonly HybridCache _cache;
    private readonly ILogger<SealedDecisionCache> _logger;
    private readonly TimeProvider _time;
    private readonly byte[] _key;
    private readonly string _kid;
    private readonly string _partition;
    private readonly TimeSpan _maxStale;
    private readonly TimeSpan _horizon;
    private readonly ConditionalWeakTable<SealedCacheEntry, Opened> _opened = new();
    private readonly ConcurrentDictionary<string, long> _invalidatedAt = new(StringComparer.Ordinal);

    public SealedDecisionCache(HybridCache cache, IOptions<PermissionAuthorizationOptions> options, ILogger<SealedDecisionCache> logger, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(options);
        var settings = options.Value.Cache;

        _cache = cache;
        _logger = logger;
        _time = time;
        _partition = string.IsNullOrWhiteSpace(settings.Partition) ? "default" : settings.Partition.Trim();
        _maxStale = settings.MaxStale > TimeSpan.Zero ? settings.MaxStale : TimeSpan.Zero;
        _horizon = new[] { settings.Assignments, settings.RolePermissions, settings.Policies, settings.Scopes }.Max() + _maxStale;

        if (string.IsNullOrEmpty(settings.SealingKey))
        {
            _key = RandomNumberGenerator.GetBytes(32);
            LogRandomSealingKey(_logger);
        }
        else
        {
            _key = HMACSHA256.HashData(Encoding.UTF8.GetBytes(settings.SealingKey), Encoding.UTF8.GetBytes($"jeffops/decision-cache/v1/{_partition}"));
        }

        _kid = Convert.ToHexString(SHA256.HashData(_key))[..16];
    }

    public string StorageKey(string key) => $"jeffops:authz:{_partition}:{key}";

    /// <summary>
    /// The value for <paramref name="key"/>, from cache or from <paramref name="factory"/>, projected with
    /// <paramref name="project"/>. The projection (for example compiling policies) runs once per cached entry instance.
    /// </summary>
    public async Task<TResult> GetOrCreateAsync<TStored, TResult>(
        string key,
        Func<CancellationToken, Task<TStored>> factory,
        Func<TStored, TResult> project,
        TimeSpan lifetime,
        CancellationToken cancellationToken)
        where TResult : notnull
    {
        var storageKey = StorageKey(key);
        var entryOptions = new HybridCacheEntryOptions { Expiration = lifetime, LocalCacheExpiration = lifetime };

        var entry = await _cache.GetOrCreateAsync(
            storageKey,
            async token => Seal(storageKey, await factory(token).ConfigureAwait(false), lifetime),
            entryOptions,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        if (TryOpen(storageKey, entry, project, out var value))
        {
            return value;
        }

        // Not ours, not for this key, tampered with, or past its sealed lifetime: replace it from the source.
        Reject(storageKey, entry);
        var fresh = Seal(storageKey, await factory(cancellationToken).ConfigureAwait(false), lifetime);
        await _cache.SetAsync(storageKey, fresh, entryOptions, cancellationToken: cancellationToken).ConfigureAwait(false);

        return TryOpen(storageKey, fresh, project, out var freshValue)
            ? freshValue
            : throw new InvalidOperationException("A freshly sealed decision-cache entry failed verification.");
    }

    /// <summary>
    /// Evicts <paramref name="key"/>, and from now on refuses entries for it sealed before this moment, so an older genuine
    /// entry put back into a shared cache isn't accepted again.
    /// </summary>
    public ValueTask RemoveAsync(string key, CancellationToken cancellationToken)
    {
        var storageKey = StorageKey(key);
        var now = _time.GetUtcNow();
        _invalidatedAt[storageKey] = now.ToUnixTimeMilliseconds();
        if (_invalidatedAt.Count > InvalidationsBeforePruning)
        {
            // Past the horizon every entry sealed before the invalidation has expired anyway.
            var forgetBefore = now.Subtract(_horizon).ToUnixTimeMilliseconds();
            foreach (var (staleKey, at) in _invalidatedAt)
            {
                if (at < forgetBefore)
                {
                    _invalidatedAt.TryRemove(KeyValuePair.Create(staleKey, at));
                }
            }
        }

        return _cache.RemoveAsync(storageKey, cancellationToken);
    }

    internal SealedCacheEntry Seal<T>(string storageKey, T value, TimeSpan lifetime)
    {
        var payload = JsonSerializer.Serialize(value);
        var now = _time.GetUtcNow();

        // Never before this process's last invalidation of the key, even if the clock stepped back since.
        var sealedAt = Math.Max(now.ToUnixTimeMilliseconds(), _invalidatedAt.GetValueOrDefault(storageKey));
        var expiresAt = now.Add(lifetime).Add(_maxStale).ToUnixTimeMilliseconds();
        return new SealedCacheEntry(_kid, payload, Mac(storageKey, expiresAt, sealedAt, payload), expiresAt, sealedAt);
    }

    private bool SealedBeforeInvalidation(string storageKey, SealedCacheEntry entry) =>
        _invalidatedAt.TryGetValue(storageKey, out var invalidatedAt) && entry.SealedAtUnixMs < invalidatedAt;

    private bool TryOpen<TStored, TResult>(string storageKey, SealedCacheEntry? entry, Func<TStored, TResult> project, out TResult value)
        where TResult : notnull
    {
        value = default!;
        if (entry?.Payload is null || entry.Mac is null || entry.Kid is null)
        {
            return false;
        }

        // Lifetime first, also for an instance already verified: a cache may keep handing back an expired instance.
        if (_time.GetUtcNow().ToUnixTimeMilliseconds() > entry.ExpiresAtUnixMs || SealedBeforeInvalidation(storageKey, entry))
        {
            return false;
        }

        if (_opened.TryGetValue(entry, out var memo) && memo.StorageKey == storageKey && memo.Value is TResult cached)
        {
            value = cached;
            return true;
        }

        if (!string.Equals(entry.Kid, _kid, StringComparison.Ordinal)
            || !CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(Mac(storageKey, entry.ExpiresAtUnixMs, entry.SealedAtUnixMs, entry.Payload)),
                Encoding.ASCII.GetBytes(entry.Mac)))
        {
            return false;
        }

        TStored? stored;
        try
        {
            stored = JsonSerializer.Deserialize<TStored>(entry.Payload);
        }
        catch (JsonException)
        {
            return false;
        }

        if (stored is null)
        {
            return false;
        }

        value = project(stored);
        _opened.AddOrUpdate(entry, new Opened(storageKey, value));
        return true;
    }

    private void Reject(string storageKey, SealedCacheEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        if (!string.Equals(entry.Kid, _kid, StringComparison.Ordinal))
        {
            LogForeignEntry(_logger, storageKey);
        }
        else if (_time.GetUtcNow().ToUnixTimeMilliseconds() > entry.ExpiresAtUnixMs)
        {
            LogExpiredEntry(_logger, storageKey);
        }
        else if (SealedBeforeInvalidation(storageKey, entry))
        {
            LogInvalidatedEntry(_logger, storageKey);
        }
        else
        {
            LogTamperedEntry(_logger, storageKey);
        }
    }

    private string Mac(string storageKey, long expiresAtUnixMs, long sealedAtUnixMs, string payload) =>
        Convert.ToBase64String(HMACSHA256.HashData(_key, Encoding.UTF8.GetBytes($"{storageKey}\n{expiresAtUnixMs}\n{sealedAtUnixMs}\n{payload}")));

    [LoggerMessage(EventId = 7101, Level = LogLevel.Warning,
        Message = "No decision-cache sealing key is configured; using a random per-process key. Replicas will not share distributed-cache entries. Set JeffOps:Authorization:Cache:SealingKey.")]
    private static partial void LogRandomSealingKey(ILogger logger);

    [LoggerMessage(EventId = 7102, Level = LogLevel.Warning,
        Message = "Decision cache entry {StorageKey} was sealed with another key (rotated key or another workload); re-reading the source.")]
    private static partial void LogForeignEntry(ILogger logger, string storageKey);

    [LoggerMessage(EventId = 7103, Level = LogLevel.Debug, Message = "Decision cache entry {StorageKey} is past its sealed lifetime; re-reading the source.")]
    private static partial void LogExpiredEntry(ILogger logger, string storageKey);

    [LoggerMessage(EventId = 7104, Level = LogLevel.Warning,
        Message = "Decision cache entry {StorageKey} failed its integrity check (possible tampering); re-reading the source.")]
    private static partial void LogTamperedEntry(ILogger logger, string storageKey);

    [LoggerMessage(EventId = 7105, Level = LogLevel.Warning,
        Message = "Decision cache entry {StorageKey} was sealed before an invalidation (possible replay); re-reading the source.")]
    private static partial void LogInvalidatedEntry(ILogger logger, string storageKey);

    private sealed record Opened(string StorageKey, object Value);
}

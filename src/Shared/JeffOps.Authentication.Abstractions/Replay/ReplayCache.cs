using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace JeffOps.Authentication.Abstractions.Replay;

/// <summary>
/// Remembers one-time values (DPoP proofs, SAML assertions and logout requests) until they could no longer be accepted, so
/// each counts once. Share one store between instances (the token server uses its database), or a value can be replayed
/// once at each instance.
/// </summary>
public interface IReplayCache
{
    /// <summary>
    /// Records <paramref name="key"/> until <paramref name="expiresAt"/>, atomically: true the first time, false when it is
    /// already recorded (a replay) or can't be recorded now (refuse rather than risk a replay).
    /// </summary>
    ValueTask<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken);
}

/// <summary>
/// Keys for <see cref="IReplayCache"/>: fixed-length, free of the values they stand for, and lowercase hex, so stores that
/// compare case-insensitively (SQL Server's default collation) keep them apart.
/// </summary>
public static class ReplayKeys
{
    /// <summary>A key for <paramref name="value"/> in <paramref name="purpose"/> (such as <c>dpop</c> or <c>saml</c>).</summary>
    public static string For(string purpose, string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(purpose);
        ArgumentNullException.ThrowIfNull(value);
        return purpose + ":" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }
}

/// <summary>
/// The in-process <see cref="IReplayCache"/>: check-and-record is atomic and memory is bounded — when
/// <see cref="Capacity"/> live values are held, new ones are refused until old ones expire (fail closed). One instance only;
/// see <see cref="IReplayCache"/> for several.
/// </summary>
public sealed class MemoryReplayCache : IReplayCache
{
    /// <summary>The default number of live values held (about 15 MB).</summary>
    public const int DefaultCapacity = 100_000;

    private readonly ConcurrentDictionary<string, long> _seen = new(StringComparer.Ordinal);
    private readonly TimeProvider _time;
    private long _nextSweep;

    /// <summary>Creates a cache holding up to <paramref name="capacity"/> live values.</summary>
    public MemoryReplayCache(TimeProvider? time = null, int capacity = DefaultCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _time = time ?? TimeProvider.System;
        Capacity = capacity;
    }

    /// <summary>The most live values held at once.</summary>
    public int Capacity { get; }

    /// <inheritdoc />
    public ValueTask<bool> TryAddAsync(string key, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(key);
        var now = _time.GetUtcNow().UtcTicks;
        if (_seen.Count >= Capacity || now >= Interlocked.Read(ref _nextSweep))
        {
            Sweep(now);
            if (_seen.Count >= Capacity)
            {
                return ValueTask.FromResult(false);
            }
        }

        var expiry = expiresAt.UtcTicks;

        // An expired entry for the same key is replaced; a live one means replay.
        while (true)
        {
            if (_seen.TryAdd(key, expiry))
            {
                return ValueTask.FromResult(true);
            }

            if (!_seen.TryGetValue(key, out var existing))
            {
                continue;
            }

            if (existing > now)
            {
                return ValueTask.FromResult(false);
            }

            if (_seen.TryUpdate(key, expiry, existing))
            {
                return ValueTask.FromResult(true);
            }
        }
    }

    private void Sweep(long now)
    {
        Interlocked.Exchange(ref _nextSweep, now + TimeSpan.TicksPerMinute);
        foreach (var (key, expiry) in _seen)
        {
            if (expiry <= now)
            {
                _seen.TryRemove(new KeyValuePair<string, long>(key, expiry));
            }
        }
    }
}

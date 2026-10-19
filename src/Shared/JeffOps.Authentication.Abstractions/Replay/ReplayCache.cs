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
/// see <see cref="IReplayCache"/> for several. Built for sustained concurrent use: values are held as 128-bit hashes (about
/// 64 bytes each), the count is kept apart rather than counted, and expired values are swept off the request path (only a
/// full cache sweeps inline, at most once a second).
/// </summary>
public sealed class MemoryReplayCache : IReplayCache
{
    /// <summary>The default number of live values held (about 32 MB when full).</summary>
    public const int DefaultCapacity = 500_000;

    private static readonly long SweepInterval = TimeSpan.TicksPerSecond * 30;
    private static readonly long FullSweepInterval = TimeSpan.TicksPerSecond;

    private readonly ConcurrentDictionary<UInt128, long> _seen = new();
    private readonly TimeProvider _time;
    private int _count;
    private long _nextSweep;
    private long _nextFullSweep;

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
        if (Volatile.Read(ref _count) >= Capacity)
        {
            // Full: make room now if anything has expired, rather than refuse values that would fit (one request a second).
            var due = Interlocked.Read(ref _nextFullSweep);
            if (now >= due && Interlocked.CompareExchange(ref _nextFullSweep, now + FullSweepInterval, due) == due)
            {
                Sweep(now);
            }
        }
        else
        {
            var due = Interlocked.Read(ref _nextSweep);
            if (now >= due && Interlocked.CompareExchange(ref _nextSweep, now + SweepInterval, due) == due)
            {
                ThreadPool.UnsafeQueueUserWorkItem(static state => state.Cache.Sweep(state.Now), (Cache: this, Now: now), preferLocal: false);
            }
        }

        var id = Hash(key);
        var expiry = expiresAt.UtcTicks;
        while (true)
        {
            // An expired entry for the same key is taken over; a live one means replay.
            if (_seen.TryGetValue(id, out var existing))
            {
                if (existing > now)
                {
                    return ValueTask.FromResult(false);
                }

                if (_seen.TryUpdate(id, expiry, existing))
                {
                    return ValueTask.FromResult(true);
                }

                continue;
            }

            // A place is reserved before the value is added, so the cache never holds more than its capacity.
            if (Interlocked.Increment(ref _count) > Capacity)
            {
                Interlocked.Decrement(ref _count);
                return ValueTask.FromResult(false);
            }

            if (_seen.TryAdd(id, expiry))
            {
                return ValueTask.FromResult(true);
            }

            Interlocked.Decrement(ref _count);
        }
    }

    /// <summary>
    /// Removes values expired at <paramref name="now"/>. Sweeps may overlap: an entry is removed (and counted off) only by
    /// the sweep that removes it, and only if unchanged, so a value taken over meanwhile stays.
    /// </summary>
    private void Sweep(long now)
    {
        foreach (var entry in _seen)
        {
            if (entry.Value <= now && _seen.TryRemove(entry))
            {
                Interlocked.Decrement(ref _count);
            }
        }
    }

    private static UInt128 Hash(string key)
    {
        var length = Encoding.UTF8.GetMaxByteCount(key.Length);
        byte[]? rented = null;
        var buffer = length <= 512 ? stackalloc byte[512] : (rented = System.Buffers.ArrayPool<byte>.Shared.Rent(length));
        try
        {
            Span<byte> digest = stackalloc byte[SHA256.HashSizeInBytes];
            SHA256.HashData(buffer[..Encoding.UTF8.GetBytes(key, buffer)], digest);
            return System.Buffers.Binary.BinaryPrimitives.ReadUInt128LittleEndian(digest);
        }
        finally
        {
            if (rented is not null)
            {
                System.Buffers.ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }
}

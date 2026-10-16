using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace JeffOps.Authentication.Abstractions.Dpop;

/// <summary>
/// Remembers used DPoP proofs (key thumbprint + <c>jti</c>) until they could no longer pass the time window, so each proof
/// works once. Check-and-record is atomic, and memory is bounded: when <see cref="Capacity"/> live proofs are held, new
/// proofs are refused until old ones expire (fail closed).
/// </summary>
/// <remarks>
/// Per process: with several instances a proof could be used once at each within its window. Server nonces
/// (<c>RequireDpopNonce</c>) narrow that window at the token server.
/// </remarks>
public sealed class DpopReplayCache
{
    /// <summary>The default number of live proofs held (about 15 MB).</summary>
    public const int DefaultCapacity = 100_000;

    private readonly ConcurrentDictionary<string, long> _seen = new(StringComparer.Ordinal);
    private long _nextSweep;

    /// <summary>Creates a cache holding up to <paramref name="capacity"/> live proofs.</summary>
    public DpopReplayCache(int capacity = DefaultCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        Capacity = capacity;
    }

    /// <summary>The most live proofs held at once.</summary>
    public int Capacity { get; }

    /// <summary>
    /// Records <paramref name="proof"/> as used until <paramref name="expiresAt"/>; false when it was used before, or when the
    /// cache is full.
    /// </summary>
    public bool TryUse(DpopProof proof, DateTimeOffset expiresAt, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(proof);
        var nowTicks = now.UtcTicks;
        if (_seen.Count >= Capacity || nowTicks >= Interlocked.Read(ref _nextSweep))
        {
            Sweep(nowTicks);
            if (_seen.Count >= Capacity)
            {
                return false;
            }
        }

        var key = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(proof.Jkt + "\n" + proof.Jti)));
        var expiry = expiresAt.UtcTicks;

        // An expired entry for the same key is replaced; a live one means replay.
        while (true)
        {
            if (_seen.TryAdd(key, expiry))
            {
                return true;
            }

            if (!_seen.TryGetValue(key, out var existing))
            {
                continue;
            }

            if (existing > nowTicks)
            {
                return false;
            }

            if (_seen.TryUpdate(key, expiry, existing))
            {
                return true;
            }
        }
    }

    private void Sweep(long nowTicks)
    {
        Interlocked.Exchange(ref _nextSweep, nowTicks + TimeSpan.TicksPerMinute);
        foreach (var (key, expiry) in _seen)
        {
            if (expiry <= nowTicks)
            {
                _seen.TryRemove(new KeyValuePair<string, long>(key, expiry));
            }
        }
    }
}

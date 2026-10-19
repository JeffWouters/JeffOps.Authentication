using System.Collections.Concurrent;

namespace JeffOps.Authentication.Abstractions.RateLimiting;

/// <summary>A number of requests allowed per window.</summary>
public sealed class RateLimit
{
    /// <summary>Creates an empty limit, for configuration binding.</summary>
    public RateLimit()
    {
    }

    /// <summary>Creates a limit of <paramref name="permitLimit"/> requests per <paramref name="window"/>.</summary>
    public RateLimit(int permitLimit, TimeSpan window)
    {
        PermitLimit = permitLimit;
        Window = window;
    }

    /// <summary>How many requests a window allows.</summary>
    public int PermitLimit { get; set; }

    /// <summary>The window's length.</summary>
    public TimeSpan Window { get; set; }
}

/// <summary>
/// Rate limits of the token server's endpoints (docs/DESIGN.md §16, D28). On by default. Each limit counts per partition
/// (client address, account, recipient, client, SCIM token) in fixed windows, per instance: with several instances a
/// partition gets that many requests at each. Bound from <see cref="SectionName"/>.
/// </summary>
public sealed class RateLimitOptions
{
    /// <summary>The configuration section the options bind from.</summary>
    public const string SectionName = "JeffOps:RateLimiting";

    /// <summary>Whether the limits apply. Default: true.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Password, code and passkey sign-in attempts from one client address. Default: 120 a minute (an office behind one
    /// address signs in together; each password check costs a hash).
    /// </summary>
    public RateLimit SignInPerAddress { get; set; } = new(120, TimeSpan.FromMinutes(1));

    /// <summary>Password sign-in attempts for one account (email address). Default: 10 a minute.</summary>
    public RateLimit SignInPerAccount { get; set; } = new(10, TimeSpan.FromMinutes(1));

    /// <summary>Requests that send mail (registration, verification, password reset, sign-in codes) from one address. Default: 20 an hour.</summary>
    public RateLimit MailPerAddress { get; set; } = new(20, TimeSpan.FromHours(1));

    /// <summary>Requests that send mail to one email address. Default: 5 an hour.</summary>
    public RateLimit MailPerRecipient { get; set; } = new(5, TimeSpan.FromHours(1));

    /// <summary>Protocol requests (authorize, token, PAR, device, introspection, revocation, …) from one address. Default: 600 a minute.</summary>
    public RateLimit ProtocolPerAddress { get; set; } = new(600, TimeSpan.FromMinutes(1));

    /// <summary>Protocol requests naming one client. Default: 3,000 a minute.</summary>
    public RateLimit ProtocolPerClient { get; set; } = new(3_000, TimeSpan.FromMinutes(1));

    /// <summary>SCIM requests with one bearer token. Default: 1,200 a minute.</summary>
    public RateLimit ScimPerToken { get; set; } = new(1_200, TimeSpan.FromMinutes(1));
}

/// <summary>
/// Counts requests per partition in fixed windows and says whether one more is allowed. In memory, per instance; bounded:
/// past <see cref="MaxPartitions"/> live partitions, new ones aren't counted (the per-address limits, of which there are
/// as many as clients, still apply). Windows that ended are dropped once a minute.
/// </summary>
public sealed class RequestRateLimiter(TimeProvider time)
{
    /// <summary>The most partitions counted at once.</summary>
    public const int MaxPartitions = 200_000;

    private static readonly long SweepInterval = TimeSpan.TicksPerMinute;

    private readonly ConcurrentDictionary<string, Counter> _counters = new(StringComparer.Ordinal);
    private long _nextSweep;

    /// <summary>
    /// Counts one request in <paramref name="partition"/> under <paramref name="limit"/>. False when the window's limit is
    /// reached; <paramref name="retryAfter"/> is then the time until the window ends.
    /// </summary>
    public bool TryAcquire(RateLimit limit, string partition, out TimeSpan retryAfter)
    {
        ArgumentNullException.ThrowIfNull(limit);
        ArgumentNullException.ThrowIfNull(partition);
        retryAfter = TimeSpan.Zero;
        if (limit.PermitLimit <= 0 || limit.Window <= TimeSpan.Zero)
        {
            return true;
        }

        var now = time.GetUtcNow().UtcTicks;
        Sweep(now);

        if (!_counters.TryGetValue(partition, out var counter))
        {
            if (_counters.Count >= MaxPartitions)
            {
                return true;
            }

            counter = _counters.GetOrAdd(partition, static _ => new Counter());
        }

        lock (counter)
        {
            var window = limit.Window.Ticks;
            if (now >= counter.EndsAt)
            {
                counter.EndsAt = now - (now % window) + window;
                counter.Count = 0;
            }

            if (counter.Count >= limit.PermitLimit)
            {
                retryAfter = TimeSpan.FromTicks(counter.EndsAt - now);
                return false;
            }

            counter.Count++;
            return true;
        }
    }

    private void Sweep(long now)
    {
        var due = Interlocked.Read(ref _nextSweep);
        if (now < due || Interlocked.CompareExchange(ref _nextSweep, now + SweepInterval, due) != due)
        {
            return;
        }

        foreach (var entry in _counters)
        {
            if (Volatile.Read(ref entry.Value.EndsAt) <= now)
            {
                _counters.TryRemove(entry);
            }
        }
    }

    private sealed class Counter
    {
        public long EndsAt;
        public int Count;
    }
}

/// <summary>Partition names for <see cref="RequestRateLimiter"/>: the limit's kind and the value counted, never mixed up.</summary>
public static class RateLimitPartitions
{
    /// <summary>The partition of <paramref name="value"/> for <paramref name="kind"/>, such as <c>signin-account</c>.</summary>
    public static string For(string kind, string? value) => kind + "\n" + (value ?? string.Empty);
}

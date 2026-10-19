using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Tracing;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace JeffOps.Authentication.LoadTests;

/// <summary>What the process did during a run: CPU, memory and GC, the thread pool, locks, and database connections.</summary>
internal sealed record RuntimeSummary(
    double CpuPercent,
    double AllocatedMbPerSecond,
    long Gen0, long Gen1, long Gen2,
    double GcPausePercent,
    long WorkingSetStartMb, long WorkingSetEndMb, long WorkingSetPeakMb,
    long HeapAfterLastGcMb, long LohMb,
    long ThreadPoolQueuePeak, long ThreadsPeak,
    long LockContentions,
    long ConnectionsOpened, long ConnectionsHeldPeak, double ConnectionHeldMsMean,
    IReadOnlyDictionary<string, double> CounterPeaks,
    IReadOnlyList<(string Type, long Bytes)> TopAllocations,
    IReadOnlyList<(double Second, long WorkingSetMb, long HeapMb)> Timeline);

/// <summary>
/// Samples the process while a scenario runs: polled runtime APIs every 250 ms, allocation ticks by type (the runtime's
/// sampled GC events), the SqlClient and HttpClient event counters, and database connections opened and held (EF Core's
/// diagnostic events, which work for every provider). Process-wide, so one scenario runs at a time.
/// </summary>
internal sealed class RuntimeSampler : IDisposable
{
    private readonly Process _process = Process.GetCurrentProcess();
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _poller;
    private readonly AllocationListener _allocations = new();
    private readonly ConnectionListener _connections = new();
    private readonly List<(double Second, long WorkingSetMb, long HeapMb)> _timeline = [];
    private readonly TimeSpan _cpuStart;
    private readonly long _allocatedStart;
    private readonly int[] _collectionsStart = [GC.CollectionCount(0), GC.CollectionCount(1), GC.CollectionCount(2)];
    private readonly TimeSpan _pauseStart = GC.GetTotalPauseDuration();
    private readonly long _contentionsStart = Monitor.LockContentionCount;
    private readonly long _workingSetStart;
    private long _workingSetPeak;
    private long _queuePeak;
    private long _threadsPeak;

    public RuntimeSampler()
    {
        _process.Refresh();
        _cpuStart = _process.TotalProcessorTime;
        _allocatedStart = GC.GetTotalAllocatedBytes(precise: true);
        _workingSetStart = _process.WorkingSet64;
        _workingSetPeak = _workingSetStart;
        _poller = PollAsync(_stop.Token);
    }

    private async Task PollAsync(CancellationToken cancellationToken)
    {
        var nextTimelinePoint = 0.0;
        while (!cancellationToken.IsCancellationRequested)
        {
            _process.Refresh();
            _workingSetPeak = Math.Max(_workingSetPeak, _process.WorkingSet64);
            _queuePeak = Math.Max(_queuePeak, ThreadPool.PendingWorkItemCount);
            _threadsPeak = Math.Max(_threadsPeak, ThreadPool.ThreadCount);
            if (_clock.Elapsed.TotalSeconds >= nextTimelinePoint)
            {
                _timeline.Add((Math.Round(_clock.Elapsed.TotalSeconds), _process.WorkingSet64 / 1_048_576, GC.GetGCMemoryInfo().HeapSizeBytes / 1_048_576));
                nextTimelinePoint += 5;
            }

            try
            {
                await Task.Delay(250, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }

    public RuntimeSummary Stop()
    {
        _stop.Cancel();
        _poller.GetAwaiter().GetResult();
        _process.Refresh();
        var elapsed = _clock.Elapsed;
        var cpu = _process.TotalProcessorTime - _cpuStart;
        var memory = GC.GetGCMemoryInfo();
        return new RuntimeSummary(
            CpuPercent: cpu.TotalMilliseconds / elapsed.TotalMilliseconds / Environment.ProcessorCount * 100,
            AllocatedMbPerSecond: (GC.GetTotalAllocatedBytes(precise: true) - _allocatedStart) / 1_048_576.0 / elapsed.TotalSeconds,
            Gen0: GC.CollectionCount(0) - _collectionsStart[0],
            Gen1: GC.CollectionCount(1) - _collectionsStart[1],
            Gen2: GC.CollectionCount(2) - _collectionsStart[2],
            GcPausePercent: (GC.GetTotalPauseDuration() - _pauseStart).TotalMilliseconds / elapsed.TotalMilliseconds * 100,
            WorkingSetStartMb: _workingSetStart / 1_048_576,
            WorkingSetEndMb: _process.WorkingSet64 / 1_048_576,
            WorkingSetPeakMb: _workingSetPeak / 1_048_576,
            HeapAfterLastGcMb: memory.HeapSizeBytes / 1_048_576,
            LohMb: memory.GenerationInfo.Length > 3 ? memory.GenerationInfo[3].SizeAfterBytes / 1_048_576 : 0,
            ThreadPoolQueuePeak: _queuePeak,
            ThreadsPeak: _threadsPeak,
            LockContentions: Monitor.LockContentionCount - _contentionsStart,
            ConnectionsOpened: _connections.Opened,
            ConnectionsHeldPeak: _connections.Peak,
            ConnectionHeldMsMean: _connections.MeanHeldMs,
            CounterPeaks: _allocations.CounterPeaks,
            TopAllocations: _allocations.Top(15),
            Timeline: [.. _timeline]);
    }

    public void Dispose()
    {
        _stop.Cancel();
        _allocations.Dispose();
        _connections.Dispose();
        _stop.Dispose();
    }

    /// <summary>Allocation ticks by type, and the peaks of the SqlClient and HttpClient event counters.</summary>
    private sealed class AllocationListener : EventListener
    {
        private readonly ConcurrentDictionary<string, long> _bytesByType = new(StringComparer.Ordinal);
        private readonly ConcurrentDictionary<string, double> _peaks = new(StringComparer.Ordinal);

        public IReadOnlyDictionary<string, double> CounterPeaks => _peaks;

        public IReadOnlyList<(string Type, long Bytes)> Top(int count) =>
            [.. _bytesByType.OrderByDescending(pair => pair.Value).Take(count).Select(pair => (pair.Key, pair.Value))];

        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            switch (eventSource.Name)
            {
                case "Microsoft-Windows-DotNETRuntime":
                    EnableEvents(eventSource, EventLevel.Verbose, (EventKeywords)0x1); // GC keyword: AllocationTick at verbose
                    break;
                case "Microsoft.Data.SqlClient.EventSource" or "System.Net.Http" or "Microsoft.AspNetCore.Hosting":
                    // Counters only: at Critical the sources' own trace events stay off (SqlClient's build strings per call).
                    EnableEvents(eventSource, EventLevel.Critical, EventKeywords.None, new Dictionary<string, string?> { ["EventCounterIntervalSec"] = "1" });
                    break;
            }
        }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            if (eventData.EventName?.StartsWith("GCAllocationTick", StringComparison.Ordinal) == true && eventData.Payload is { } payload && eventData.PayloadNames is { } names)
            {
                var type = names.IndexOf("TypeName") is var typeIndex and >= 0 ? payload[typeIndex] as string : null;
                var amount = names.IndexOf("AllocationAmount64") is var amountIndex and >= 0 ? Convert.ToInt64(payload[amountIndex], System.Globalization.CultureInfo.InvariantCulture) : 100_000;
                _bytesByType.AddOrUpdate(type ?? "?", amount, (_, total) => total + amount);
            }
            else if (eventData.EventName == "EventCounters" && eventData.Payload?[0] is IDictionary<string, object> counter
                && counter.TryGetValue("Name", out var name) && name is string counterName)
            {
                var value = counter.TryGetValue("Max", out var max) ? Convert.ToDouble(max, System.Globalization.CultureInfo.InvariantCulture)
                    : counter.TryGetValue("Increment", out var increment) ? Convert.ToDouble(increment, System.Globalization.CultureInfo.InvariantCulture)
                    : 0;
                _peaks.AddOrUpdate($"{eventData.EventSource.Name}/{counterName}", value, (_, previous) => Math.Max(previous, value));
            }
        }
    }

    /// <summary>Database connections opened and held, from EF Core's diagnostic events (every DbContext in the process).</summary>
    private sealed class ConnectionListener : IObserver<DiagnosticListener>, IObserver<KeyValuePair<string, object?>>, IDisposable
    {
        private readonly IDisposable _subscription;
        private readonly List<IDisposable> _listeners = [];
        private long _open;
        private long _peak;
        private long _opened;
        private long _heldTicks;
        private readonly ConcurrentDictionary<Guid, long> _openedAt = new();

        public ConnectionListener() => _subscription = DiagnosticListener.AllListeners.Subscribe(this);

        public long Opened => Interlocked.Read(ref _opened);

        public long Peak => Interlocked.Read(ref _peak);

        public double MeanHeldMs => Opened == 0 ? 0 : TimeSpan.FromTicks(Interlocked.Read(ref _heldTicks)).TotalMilliseconds / Opened;

        public void OnNext(DiagnosticListener value)
        {
            if (value.Name == DbLoggerCategory.Name)
            {
                lock (_listeners)
                {
                    _listeners.Add(value.Subscribe(this));
                }
            }
        }

        public void OnNext(KeyValuePair<string, object?> value)
        {
            if (value.Key == RelationalEventId.ConnectionOpened.Name && value.Value is ConnectionEndEventData opened)
            {
                Interlocked.Increment(ref _opened);
                _openedAt[opened.ConnectionId] = Stopwatch.GetTimestamp();
                var open = Interlocked.Increment(ref _open);
                long peak;
                while (open > (peak = Interlocked.Read(ref _peak)) && Interlocked.CompareExchange(ref _peak, open, peak) != peak)
                {
                }
            }
            else if (value.Key == RelationalEventId.ConnectionClosed.Name && value.Value is ConnectionEndEventData closed)
            {
                Interlocked.Decrement(ref _open);
                if (_openedAt.TryRemove(closed.ConnectionId, out var at))
                {
                    Interlocked.Add(ref _heldTicks, Stopwatch.GetElapsedTime(at).Ticks);
                }
            }
        }

        public void OnCompleted()
        {
        }

        public void OnError(Exception error)
        {
        }

        public void Dispose()
        {
            _subscription.Dispose();
            lock (_listeners)
            {
                _listeners.ForEach(listener => listener.Dispose());
            }
        }
    }
}

/// <summary>Latencies of one scenario, kept whole so percentiles are exact.</summary>
internal sealed class LatencyRecorder
{
    private readonly ConcurrentBag<double> _milliseconds = [];
    private readonly ConcurrentDictionary<string, int> _errors = new(StringComparer.Ordinal);

    public void Record(TimeSpan elapsed) => _milliseconds.Add(elapsed.TotalMilliseconds);

    public void Error(string kind) => _errors.AddOrUpdate(kind, 1, (_, count) => count + 1);

    public int Count => _milliseconds.Count;

    public IReadOnlyDictionary<string, int> Errors => _errors;

    public (double P50, double P95, double P99, double Max) Percentiles()
    {
        var sorted = _milliseconds.ToArray();
        Array.Sort(sorted);
        double At(double fraction) => sorted.Length == 0 ? 0 : sorted[Math.Min(sorted.Length - 1, (int)(fraction * sorted.Length))];
        return (At(0.50), At(0.95), At(0.99), sorted.Length == 0 ? 0 : sorted[^1]);
    }
}

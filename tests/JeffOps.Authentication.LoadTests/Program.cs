using System.Diagnostics;
using System.Globalization;
using System.Text;
using JeffOps.Authentication.Tests.Shared;

namespace JeffOps.Authentication.LoadTests;

/// <summary>
/// The load harness (docs/DESIGN.md §20). Options: --scenario NAME|all (mixed, for soak runs, only by name), --users N, --duration SECONDS, --warmup SECONDS,
/// --logging (format every log message at Information, as a host's default configuration does), --logging-recommended (the same with
/// OpenIddict and YARP at Warning, as docs/getting-started.md recommends), --directory-latency MS,
/// --database-latency MS (SQLite only), --report PATH, --prune (after the run, one timed pruning pass with every spent row eligible). The database is SQLite, or SQL Server with JEFFOPS_TEST_DATABASE=SqlServer.
/// </summary>
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        string Option(string name, string fallback) => args.SkipWhile(arg => arg != name).Skip(1).FirstOrDefault() ?? fallback;
        var scenarioName = Option("--scenario", "all");
        var users = int.Parse(Option("--users", "16"), CultureInfo.InvariantCulture);
        var duration = TimeSpan.FromSeconds(double.Parse(Option("--duration", "20"), CultureInfo.InvariantCulture));
        var warmUp = TimeSpan.FromSeconds(double.Parse(Option("--warmup", "5"), CultureInfo.InvariantCulture));
        var options = new StackOptions(
            Logging: args.Contains("--logging") || args.Contains("--logging-recommended"),
            DirectoryLatency: TimeSpan.FromMilliseconds(double.Parse(Option("--directory-latency", "0"), CultureInfo.InvariantCulture)),
            DatabaseLatency: TimeSpan.FromMilliseconds(double.Parse(Option("--database-latency", "0"), CultureInfo.InvariantCulture)),
            RecommendedLogLevels: args.Contains("--logging-recommended"));
        var reportPath = Option("--report", Path.Combine(Path.GetTempPath(), "jeffops-load.md"));

        ThreadPool.GetMinThreads(out var minWorkers, out _);
        var report = new StringBuilder();
        report.AppendLine(CultureInfo.InvariantCulture, $"# Load ({(TestDatabase.SqlServer ? "SQL Server" : "SQLite")}, {users} virtual users, {duration.TotalSeconds} s each, logging {(options.RecommendedLogLevels ? "recommended" : options.Logging ? "on" : "off")}, directory latency {options.DirectoryLatency.TotalMilliseconds} ms, database latency {options.DatabaseLatency.TotalMilliseconds} ms)");
        report.AppendLine(CultureInfo.InvariantCulture, $"{Environment.ProcessorCount} cores, server GC {System.Runtime.GCSettings.IsServerGC}, thread pool minimum {minWorkers}, process {Environment.ProcessId}").AppendLine();

        var startup = Stopwatch.StartNew();
        await using var stack = await Stack.StartAsync(options);
        startup.Stop();
        Process.GetCurrentProcess().Refresh();
        report.AppendLine(CultureInfo.InvariantCulture, $"Startup (four hosts, databases created/migrated): {startup.Elapsed.TotalSeconds:F1} s, working set {Process.GetCurrentProcess().WorkingSet64 / 1_048_576} MB");
        await Task.Delay(TimeSpan.FromSeconds(5));
        GC.Collect();
        Process.GetCurrentProcess().Refresh();
        report.AppendLine(CultureInfo.InvariantCulture, $"Idle after 5 s and a full GC: working set {Process.GetCurrentProcess().WorkingSet64 / 1_048_576} MB, managed heap {GC.GetGCMemoryInfo().HeapSizeBytes / 1_048_576} MB").AppendLine();

        report.AppendLine("| Scenario | Ops/s | p50 ms | p95 ms | p99 ms | max ms | Errors | CPU % | Alloc MB/s | Gen0/1/2 | GC pause % | WS start→peak MB | Heap MB | TP queue peak | Threads peak | Lock contentions | DB conns opened/s | DB conns held peak | Held ms mean |");
        report.AppendLine("|---|---:|---:|---:|---:|---:|---:|---:|---:|---|---:|---|---:|---:|---:|---:|---:|---:|---:|");
        var details = new StringBuilder();
        foreach (var scenario in (scenarioName == "all" ? Scenarios.All : Scenarios.Named.Where(scenario => scenario.Name == scenarioName)))
        {
            Console.WriteLine($"{scenario.Name}…");
            Runner.Result result;
            try
            {
                result = await Runner.RunAsync(stack, scenario, users, duration, warmUp);
            }
            catch (Exception exception)
            {
                report.AppendLine(CultureInfo.InvariantCulture, $"| {scenario.Name} | failed: {exception.GetType().Name}: {exception.Message.ReplaceLineEndings(" ")[..Math.Min(150, exception.Message.Length)]} |");
                continue;
            }

            var runtime = result.Runtime;
            report.AppendLine(CultureInfo.InvariantCulture,
                $"| {result.Scenario} | {result.PerSecond:F0} | {result.Latency.P50:F1} | {result.Latency.P95:F1} | {result.Latency.P99:F1} | {result.Latency.Max:F0} | {result.Errors.Values.Sum()} | {runtime.CpuPercent:F0} | {runtime.AllocatedMbPerSecond:F0} | {runtime.Gen0}/{runtime.Gen1}/{runtime.Gen2} | {runtime.GcPausePercent:F1} | {runtime.WorkingSetStartMb}→{runtime.WorkingSetPeakMb} | {runtime.HeapAfterLastGcMb} | {runtime.ThreadPoolQueuePeak} | {runtime.ThreadsPeak} | {runtime.LockContentions} | {runtime.ConnectionsOpened / result.Duration.TotalSeconds:F0} | {runtime.ConnectionsHeldPeak} | {runtime.ConnectionHeldMsMean:F2} |");

            details.AppendLine(CultureInfo.InvariantCulture, $"## {result.Scenario}").AppendLine();
            details.AppendLine(CultureInfo.InvariantCulture, $"Per operation: {runtime.AllocatedMbPerSecond * 1024 / Math.Max(result.PerSecond, 1):F0} KB allocated, {runtime.ConnectionsOpened / (double)Math.Max(result.Operations, 1):F1} connections opened, {runtime.CpuPercent * Environment.ProcessorCount * 10 / Math.Max(result.PerSecond, 1):F2} ms CPU");
            details.AppendLine().AppendLine("Rows added per operation: " + string.Join(", ", result.RowsAdded.Select(pair => $"{pair.Key} {pair.Value / (double)Math.Max(result.Operations, 1):F2}")));
            if (result.Errors.Count > 0)
            {
                details.AppendLine().AppendLine("Errors: " + string.Join("; ", result.Errors.Select(pair => $"{pair.Value}× {pair.Key}")));
            }

            details.AppendLine().AppendLine("Top allocations (sampled): " + string.Join(", ", runtime.TopAllocations.Select(entry => $"{entry.Type} {entry.Bytes / 1_048_576.0:F0} MB")));
            if (runtime.CounterPeaks.Count > 0)
            {
                details.AppendLine().AppendLine("Counter peaks: " + string.Join(", ", runtime.CounterPeaks.Where(pair => pair.Value > 0).OrderBy(pair => pair.Key).Select(pair => $"{pair.Key}={pair.Value:F0}")));
            }

            details.AppendLine().AppendLine("Timeline (s: working set MB / heap MB): " + string.Join(", ", runtime.Timeline.Select(point => $"{point.Second}: {point.WorkingSetMb}/{point.HeapMb}")));
            details.AppendLine();
        }

        if (args.Contains("--prune"))
        {
            var before = await stack.RowCountsAsync();
            var (tokens, authorizations, elapsed) = await stack.PruneSpentAsync();
            report.AppendLine().AppendLine(CultureInfo.InvariantCulture,
                $"Prune pass (every spent row eligible): {before["tokens"]} tokens and {before["authorizations"]} authorizations before; removed {tokens} and {authorizations} in {elapsed.TotalMilliseconds:F0} ms");
        }

        var categories = FormattingLoggerProvider.ByCategory.IsEmpty ? ""
            : " (" + string.Join(", ", FormattingLoggerProvider.ByCategory.OrderByDescending(pair => pair.Value).Take(8).Select(pair => $"{pair.Key} {pair.Value}")) + ")";
        report.AppendLine().AppendLine(CultureInfo.InvariantCulture, $"Log messages formatted: {FormattingLoggerProvider.Messages}{categories}").AppendLine().Append(details);
        await File.WriteAllTextAsync(reportPath, report.ToString());
        Console.WriteLine(report.ToString());
        return 0;
    }
}

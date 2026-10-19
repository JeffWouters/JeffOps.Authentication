using System.Collections.Concurrent;
using JeffOps.Authentication.Abstractions.Auditing;
using Microsoft.Extensions.Logging;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>Keeps every formatted log message with its category, to check what reaches the log.</summary>
internal sealed class RecordingLogs : ILoggerProvider
{
    public ConcurrentQueue<(string Category, string Message)> Entries { get; } = new();

    /// <summary>The messages this library logged (categories under <c>JeffOps.</c>).</summary>
    public IReadOnlyList<string> Messages => [.. Entries.Where(entry => entry.Category.StartsWith("JeffOps.", StringComparison.Ordinal)).Select(entry => entry.Message)];

    public ILogger CreateLogger(string categoryName) => new Logger(categoryName, Entries);

    public void Dispose()
    {
    }

    private sealed class Logger(string category, ConcurrentQueue<(string Category, string Message)> entries) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            entries.Enqueue((category, formatter(state, exception)));
    }
}

/// <summary>Keeps every audit record written.</summary>
internal sealed class RecordingAudit : IAuditSink
{
    public ConcurrentQueue<AuditRecord> Records { get; } = new();

    public Task WriteAsync(AuditRecord record, CancellationToken cancellationToken)
    {
        Records.Enqueue(record);
        return Task.CompletedTask;
    }

    public IReadOnlyList<string> Actions => [.. Records.Select(record => record.Action)];
}

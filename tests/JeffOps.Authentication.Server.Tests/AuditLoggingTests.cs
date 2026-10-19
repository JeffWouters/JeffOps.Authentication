using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Infrastructure.Defaults;
using Microsoft.Extensions.Logging;

namespace JeffOps.Authentication.Server.Tests;

public sealed class AuditLoggingTests
{
    [Fact]
    public async Task The_logging_audit_sink_writes_the_details_without_line_breaks()
    {
        var logger = new CapturingLogger();
        var sink = new LoggingAuditSink(logger);

        await sink.WriteAsync(
            new AuditRecord("group_assignment.revoked", "group_assignment", "42")
            {
                Severity = AuditSeverity.Warning,
                Details = new Dictionary<string, string?> { ["role"] = "Admin\r\nAudit forged", ["group"] = "g1" },
            },
            TestContext.Current.CancellationToken);

        var (level, message, state) = logger.Entries.ShouldHaveSingleItem();
        level.ShouldBe(LogLevel.Warning);
        message.ShouldContain("group=g1, role=Admin  Audit forged");
        message.ShouldNotContain("\n");
        state.ShouldContain(pair => pair.Key == "Details");
    }

    private sealed class CapturingLogger : ILogger<LoggingAuditSink>
    {
        public List<(LogLevel Level, string Message, IReadOnlyList<KeyValuePair<string, object?>> State)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        // The state may be pooled and reused once Log returns: copy it.
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception), state is IEnumerable<KeyValuePair<string, object?>> pairs ? [.. pairs] : []));
    }
}

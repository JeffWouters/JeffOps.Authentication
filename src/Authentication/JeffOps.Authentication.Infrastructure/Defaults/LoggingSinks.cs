using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Abstractions.Messaging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace JeffOps.Authentication.Infrastructure.Defaults;

/// <summary>
/// The default <see cref="IAuditSink"/>: writes audit records, with their details, to the log. Replace with the host's audit
/// store.
/// </summary>
internal sealed partial class LoggingAuditSink(ILogger<LoggingAuditSink> logger) : IAuditSink
{
    public Task WriteAsync(AuditRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);

        var details = FormatDetails(record.Details);
        if (record.Severity == AuditSeverity.Warning)
        {
            LogWarning(logger, record.Action, record.TargetType, record.TargetId, record.ActorId, record.TenantId, details);
        }
        else
        {
            LogInformation(logger, record.Action, record.TargetType, record.TargetId, record.ActorId, record.TenantId, details);
        }

        return Task.CompletedTask;
    }

    /// <summary><c>key=value</c> pairs in key order, with control characters blanked so a detail can't forge a log line.</summary>
    internal static string FormatDetails(IReadOnlyDictionary<string, string?> details) =>
        string.Join(", ", details.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => $"{Clean(pair.Key)}={Clean(pair.Value)}"));

    private static string Clean(string? value) =>
        value is null ? string.Empty : string.Create(value.Length, value, static (span, text) =>
        {
            for (var i = 0; i < text.Length; i++)
            {
                span[i] = char.IsControl(text[i]) ? ' ' : text[i];
            }
        });

    [LoggerMessage(EventId = 8301, Level = LogLevel.Information, Message = "Audit {Action} on {TargetType} {TargetId} by {ActorId} in {TenantId}: {Details}")]
    private static partial void LogInformation(ILogger logger, string action, string targetType, string targetId, Guid? actorId, Guid? tenantId, string details);

    [LoggerMessage(EventId = 8302, Level = LogLevel.Warning, Message = "Audit {Action} on {TargetType} {TargetId} by {ActorId} in {TenantId}: {Details}")]
    private static partial void LogWarning(ILogger logger, string action, string targetType, string targetId, Guid? actorId, Guid? tenantId, string details);
}

/// <summary>
/// The default <see cref="IEventPublisher"/>: delivers events to this host's own <see cref="IIntegrationEventHandler{TEvent}"/>s
/// (for example co-hosted authorization management) and logs them. Replace with a broker adapter to reach other services.
/// </summary>
internal sealed partial class InProcessEventPublisher(IServiceScopeFactory scopes, ILogger<InProcessEventPublisher> logger) : IEventPublisher
{
    public async Task PublishAsync(IntegrationEvent integrationEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(integrationEvent);

        var handlerType = typeof(IIntegrationEventHandler<>).MakeGenericType(integrationEvent.GetType());
        var method = handlerType.GetMethod(nameof(IIntegrationEventHandler<IntegrationEvent>.HandleAsync))!;
        await using var scope = scopes.CreateAsyncScope();
        var handlers = scope.ServiceProvider.GetServices(handlerType).ToList();
        foreach (var handler in handlers)
        {
            await ((Task)method.Invoke(handler, [integrationEvent, cancellationToken])!).ConfigureAwait(false);
        }

        LogPublished(logger, integrationEvent.Type, integrationEvent.Id, handlers.Count);
    }

    [LoggerMessage(EventId = 8303, Level = LogLevel.Debug, Message = "Integration event {Type} ({Id}) delivered to {Count} local handlers.")]
    private static partial void LogPublished(ILogger logger, string type, Guid id, int count);
}

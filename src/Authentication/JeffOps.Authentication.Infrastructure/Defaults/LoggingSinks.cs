using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Abstractions.Messaging;
using Microsoft.Extensions.Logging;

namespace JeffOps.Authentication.Infrastructure.Defaults;

/// <summary>The default <see cref="IAuditSink"/>: writes audit records to the log. Replace with the host's audit store.</summary>
internal sealed partial class LoggingAuditSink(ILogger<LoggingAuditSink> logger) : IAuditSink
{
    public Task WriteAsync(AuditRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);

        if (record.Severity == AuditSeverity.Warning)
        {
            LogWarning(logger, record.Action, record.TargetType, record.TargetId, record.ActorId, record.TenantId);
        }
        else
        {
            LogInformation(logger, record.Action, record.TargetType, record.TargetId, record.ActorId, record.TenantId);
        }

        return Task.CompletedTask;
    }

    [LoggerMessage(EventId = 8301, Level = LogLevel.Information, Message = "Audit {Action} on {TargetType} {TargetId} by {ActorId} in {TenantId}")]
    private static partial void LogInformation(ILogger logger, string action, string targetType, string targetId, Guid? actorId, Guid? tenantId);

    [LoggerMessage(EventId = 8302, Level = LogLevel.Warning, Message = "Audit {Action} on {TargetType} {TargetId} by {ActorId} in {TenantId}")]
    private static partial void LogWarning(ILogger logger, string action, string targetType, string targetId, Guid? actorId, Guid? tenantId);
}

/// <summary>The default <see cref="IEventPublisher"/>: logs events without delivering them. Replace with a broker adapter.</summary>
internal sealed partial class LoggingEventPublisher(ILogger<LoggingEventPublisher> logger) : IEventPublisher
{
    public Task PublishAsync(IntegrationEvent integrationEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(integrationEvent);
        LogPublished(logger, integrationEvent.Type, integrationEvent.Id);
        return Task.CompletedTask;
    }

    [LoggerMessage(EventId = 8303, Level = LogLevel.Debug, Message = "Integration event {Type} ({Id}) raised; no publisher is configured.")]
    private static partial void LogPublished(ILogger logger, string type, Guid id);
}

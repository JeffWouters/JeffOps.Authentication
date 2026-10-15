using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Abstractions.Messaging;
using Microsoft.Extensions.DependencyInjection;
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

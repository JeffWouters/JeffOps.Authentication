namespace JeffOps.Authentication.Abstractions.Messaging;

/// <summary>
/// An event published to other services. <see cref="Type"/> is a stable, versioned name (for example
/// <c>authorization.policy.changed.v1</c>) that broker adapters route on. JeffOps libraries reference no broker;
/// hosts plug one in through <see cref="IEventPublisher"/> and by dispatching received events to
/// <see cref="IIntegrationEventHandler{TEvent}"/> (docs/DESIGN.md §15, D7).
/// </summary>
public abstract record IntegrationEvent
{
    public Guid Id { get; init; } = Guid.NewGuid();

    /// <summary>When the event happened; set by the publisher from its <see cref="TimeProvider"/>.</summary>
    public DateTimeOffset OccurredAt { get; init; }

    /// <summary>The stable, versioned event name.</summary>
    public abstract string Type { get; }
}

/// <summary>
/// Publishes integration events. Implementations decide delivery (outbox, broker, in-process).
/// </summary>
public interface IEventPublisher
{
    Task PublishAsync(IntegrationEvent integrationEvent, CancellationToken cancellationToken);
}

/// <summary>
/// Handles an integration event of type <typeparamref name="TEvent"/> received from another service. Broker adapters
/// resolve every registered handler for an incoming event's type and call it.
/// </summary>
public interface IIntegrationEventHandler<in TEvent>
    where TEvent : IntegrationEvent
{
    Task HandleAsync(TEvent integrationEvent, CancellationToken cancellationToken);
}

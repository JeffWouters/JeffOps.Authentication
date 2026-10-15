using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.SharedKernel.Domain;

/// <summary>
/// Dispatches domain events to their registered handlers, in order, one event at a time.
/// </summary>
public interface IDomainEventDispatcher
{
    Task DispatchAsync(IEnumerable<IDomainEvent> domainEvents, CancellationToken cancellationToken);
}

/// <summary>
/// Resolves <see cref="IDomainEventHandler{TEvent}"/> for each event's runtime type from the container.
/// </summary>
public sealed class DomainEventDispatcher(IServiceProvider services) : IDomainEventDispatcher
{
    private static readonly ConcurrentDictionary<Type, Invoker> Invokers = new();

    public async Task DispatchAsync(IEnumerable<IDomainEvent> domainEvents, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domainEvents);

        foreach (var domainEvent in domainEvents)
        {
            var invoker = Invokers.GetOrAdd(
                domainEvent.GetType(),
                static eventType => (Invoker)Activator.CreateInstance(typeof(Invoker<>).MakeGenericType(eventType))!);

            await invoker.InvokeAsync(services, domainEvent, cancellationToken).ConfigureAwait(false);
        }
    }

    private abstract class Invoker
    {
        public abstract Task InvokeAsync(IServiceProvider services, IDomainEvent domainEvent, CancellationToken cancellationToken);
    }

    private sealed class Invoker<TEvent> : Invoker
        where TEvent : IDomainEvent
    {
        public override async Task InvokeAsync(IServiceProvider services, IDomainEvent domainEvent, CancellationToken cancellationToken)
        {
            foreach (var handler in services.GetServices<IDomainEventHandler<TEvent>>())
            {
                await handler.HandleAsync((TEvent)domainEvent, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}

namespace JeffOps.Authentication.SharedKernel.Domain;

/// <summary>
/// Something that happened in the domain. Raised by aggregates, dispatched in-process after the unit of work saves.
/// Handlers that must reach other systems translate it into an integration event (docs/DESIGN.md §6.1).
/// </summary>
public interface IDomainEvent;

/// <summary>
/// Reacts to a domain event of type <typeparamref name="TEvent"/>.
/// </summary>
public interface IDomainEventHandler<in TEvent>
    where TEvent : IDomainEvent
{
    Task HandleAsync(TEvent domainEvent, CancellationToken cancellationToken);
}

/// <summary>
/// Implemented by aggregates so a unit of work can collect and clear their pending events.
/// </summary>
public interface IHasDomainEvents
{
    IReadOnlyCollection<IDomainEvent> DomainEvents { get; }

    void ClearDomainEvents();
}

/// <summary>
/// Root of a consistency boundary. Only aggregate roots raise domain events.
/// </summary>
public abstract class AggregateRoot<TId> : Entity<TId>, IHasDomainEvents
    where TId : notnull
{
    private readonly List<IDomainEvent> _domainEvents = [];

    protected AggregateRoot(TId id)
        : base(id)
    {
    }

    /// <summary>For ORM materialisation only.</summary>
    protected AggregateRoot()
    {
    }

    public IReadOnlyCollection<IDomainEvent> DomainEvents => _domainEvents.AsReadOnly();

    public void ClearDomainEvents() => _domainEvents.Clear();

    protected void Raise(IDomainEvent domainEvent)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);
        _domainEvents.Add(domainEvent);
    }
}

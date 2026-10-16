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
    /// <summary>Reacts to <paramref name="domainEvent"/>, after the unit of work that raised it has saved.</summary>
    Task HandleAsync(TEvent domainEvent, CancellationToken cancellationToken);
}

/// <summary>
/// Implemented by aggregates so a unit of work can collect and clear their pending events.
/// </summary>
public interface IHasDomainEvents
{
    /// <summary>The events raised since they were last cleared, in the order they were raised.</summary>
    IReadOnlyCollection<IDomainEvent> DomainEvents { get; }

    /// <summary>Discards the pending events; the unit of work calls it once it has collected them.</summary>
    void ClearDomainEvents();
}

/// <summary>
/// Root of a consistency boundary. Only aggregate roots raise domain events.
/// </summary>
public abstract class AggregateRoot<TId> : Entity<TId>, IHasDomainEvents
    where TId : notnull
{
    private readonly List<IDomainEvent> _domainEvents = [];

    /// <summary>Creates an aggregate root with the given identity.</summary>
    protected AggregateRoot(TId id)
        : base(id)
    {
    }

    /// <summary>For ORM materialisation only.</summary>
    protected AggregateRoot()
    {
    }

    /// <inheritdoc />
    public IReadOnlyCollection<IDomainEvent> DomainEvents => _domainEvents.AsReadOnly();

    /// <inheritdoc />
    public void ClearDomainEvents() => _domainEvents.Clear();

    /// <summary>Records <paramref name="domainEvent"/> for dispatch after the next save.</summary>
    protected void Raise(IDomainEvent domainEvent)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);
        _domainEvents.Add(domainEvent);
    }
}

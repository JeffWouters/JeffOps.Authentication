namespace JeffOps.Authentication.SharedKernel.Domain;

/// <summary>
/// Marker for strongly-typed identifiers, e.g. <c>public readonly record struct AccountId(Guid Value) : IStronglyTypedId&lt;Guid&gt;</c>.
/// </summary>
public interface IStronglyTypedId<out TValue>
{
    TValue Value { get; }
}

/// <summary>
/// An object defined by its identity. Two entities are equal when they have the same type and id.
/// </summary>
public abstract class Entity<TId> : IEquatable<Entity<TId>>
    where TId : notnull
{
    protected Entity(TId id) => Id = id;

    /// <summary>For ORM materialisation only.</summary>
    protected Entity() => Id = default!;

    public TId Id { get; private init; }

    public bool Equals(Entity<TId>? other) =>
        other is not null && other.GetType() == GetType() && EqualityComparer<TId>.Default.Equals(Id, other.Id);

    public override bool Equals(object? obj) => obj is Entity<TId> other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(GetType(), Id);

    public static bool operator ==(Entity<TId>? left, Entity<TId>? right) => Equals(left, right);

    public static bool operator !=(Entity<TId>? left, Entity<TId>? right) => !Equals(left, right);
}

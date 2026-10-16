namespace JeffOps.Authentication.Abstractions.Messaging;

/// <summary>
/// A tenant group's members changed (or the group was created). Carries the full member list, so a consumer can replace its
/// copy and never drift; <see cref="Added"/> and <see cref="Removed"/> say whose access changed.
/// </summary>
/// <param name="TenantId">The tenant that owns the group.</param>
/// <param name="GroupId">The group.</param>
/// <param name="DisplayName">The group's display name.</param>
/// <param name="Members">Every current member's account id.</param>
/// <param name="Added">Accounts that joined in this change.</param>
/// <param name="Removed">Accounts that left in this change.</param>
public sealed record GroupMembershipChangedEvent(
    Guid TenantId,
    Guid GroupId,
    string DisplayName,
    IReadOnlyList<Guid> Members,
    IReadOnlyList<Guid> Added,
    IReadOnlyList<Guid> Removed) : IntegrationEvent
{
    /// <summary>The versioned event type name of <see cref="GroupMembershipChangedEvent"/>.</summary>
    public const string EventType = "auth.group.membership_changed.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

/// <summary>A tenant group was deleted; its role assignments no longer apply.</summary>
/// <param name="TenantId">The tenant that owned the group.</param>
/// <param name="GroupId">The deleted group.</param>
/// <param name="FormerMembers">The accounts that were members when it was deleted, whose access may have changed.</param>
public sealed record GroupDeletedEvent(Guid TenantId, Guid GroupId, IReadOnlyList<Guid> FormerMembers) : IntegrationEvent
{
    /// <summary>The versioned event type name of <see cref="GroupDeletedEvent"/>.</summary>
    public const string EventType = "auth.group.deleted.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

namespace JeffOps.Authentication.Abstractions.Messaging;

/// <summary>
/// A tenant group's members changed (or the group was created). Carries the full member list, so a consumer can replace its
/// copy and never drift; <see cref="Added"/> and <see cref="Removed"/> say whose access changed.
/// </summary>
public sealed record GroupMembershipChangedEvent(
    Guid TenantId,
    Guid GroupId,
    string DisplayName,
    IReadOnlyList<Guid> Members,
    IReadOnlyList<Guid> Added,
    IReadOnlyList<Guid> Removed) : IntegrationEvent
{
    public const string EventType = "auth.group.membership_changed.v1";

    public override string Type => EventType;
}

/// <summary>A tenant group was deleted; its role assignments no longer apply.</summary>
public sealed record GroupDeletedEvent(Guid TenantId, Guid GroupId, IReadOnlyList<Guid> FormerMembers) : IntegrationEvent
{
    public const string EventType = "auth.group.deleted.v1";

    public override string Type => EventType;
}

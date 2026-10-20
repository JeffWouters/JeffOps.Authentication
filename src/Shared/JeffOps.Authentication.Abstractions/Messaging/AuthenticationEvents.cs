namespace JeffOps.Authentication.Abstractions.Messaging;

/// <summary>An account was created, by registration or on its first external sign-in.</summary>
/// <param name="AccountId">The new account.</param>
/// <param name="Email">The account's email address.</param>
public sealed record AccountRegisteredEvent(Guid AccountId, string Email) : IntegrationEvent
{
    /// <summary>The versioned event type name of <see cref="AccountRegisteredEvent"/>.</summary>
    public const string EventType = "auth.account.registered.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

/// <summary>An account signed in interactively.</summary>
/// <param name="AccountId">The account that signed in.</param>
/// <param name="TenantId">The tenant the session was started in; null when the account has no tenant membership.</param>
public sealed record AccountSignedInEvent(Guid AccountId, Guid? TenantId) : IntegrationEvent
{
    /// <summary>The versioned event type name of <see cref="AccountSignedInEvent"/>.</summary>
    public const string EventType = "auth.account.signed_in.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

/// <summary>An account was disabled or re-enabled by an operator.</summary>
/// <param name="AccountId">The account whose status changed.</param>
/// <param name="Disabled">True when the account was disabled; false when it was re-enabled.</param>
public sealed record AccountStatusChangedEvent(Guid AccountId, bool Disabled) : IntegrationEvent
{
    /// <summary>The versioned event type name of <see cref="AccountStatusChangedEvent"/>.</summary>
    public const string EventType = "auth.account.status_changed.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

/// <summary>
/// An account was deleted: by its user, an operator, or for inactivity. Services drop what they keep about it, by their own
/// retention rules.
/// </summary>
/// <param name="AccountId">The deleted account.</param>
/// <param name="Reason">Why: <c>requested</c>, <c>operator</c> or <c>inactive</c>.</param>
public sealed record AccountDeletedEvent(Guid AccountId, string Reason) : IntegrationEvent
{
    /// <summary>The versioned event type name of <see cref="AccountDeletedEvent"/>.</summary>
    public const string EventType = "auth.account.deleted.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

/// <summary>A personal access token was created.</summary>
/// <param name="TokenId">The new token.</param>
/// <param name="AccountId">The account that owns it.</param>
public sealed record PersonalAccessTokenCreatedEvent(Guid TokenId, Guid AccountId) : IntegrationEvent
{
    /// <summary>The versioned event type name of <see cref="PersonalAccessTokenCreatedEvent"/>.</summary>
    public const string EventType = "auth.pat.created.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

/// <summary>A personal access token was revoked.</summary>
/// <param name="TokenId">The revoked token.</param>
/// <param name="AccountId">The account that owns it.</param>
public sealed record PersonalAccessTokenRevokedEvent(Guid TokenId, Guid AccountId) : IntegrationEvent
{
    /// <summary>The versioned event type name of <see cref="PersonalAccessTokenRevokedEvent"/>.</summary>
    public const string EventType = "auth.pat.revoked.v1";

    /// <inheritdoc />
    public override string Type => EventType;
}

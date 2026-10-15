namespace JeffOps.Authentication.Abstractions.Messaging;

/// <summary>An account was created, by registration or on its first external sign-in.</summary>
public sealed record AccountRegisteredEvent(Guid AccountId, string Email) : IntegrationEvent
{
    public const string EventType = "auth.account.registered.v1";

    public override string Type => EventType;
}

/// <summary>An account signed in interactively.</summary>
public sealed record AccountSignedInEvent(Guid AccountId, Guid? TenantId) : IntegrationEvent
{
    public const string EventType = "auth.account.signed_in.v1";

    public override string Type => EventType;
}

/// <summary>An account was disabled or re-enabled by an operator.</summary>
public sealed record AccountStatusChangedEvent(Guid AccountId, bool Disabled) : IntegrationEvent
{
    public const string EventType = "auth.account.status_changed.v1";

    public override string Type => EventType;
}

/// <summary>A personal access token was created.</summary>
public sealed record PersonalAccessTokenCreatedEvent(Guid TokenId, Guid AccountId) : IntegrationEvent
{
    public const string EventType = "auth.pat.created.v1";

    public override string Type => EventType;
}

/// <summary>A personal access token was revoked.</summary>
public sealed record PersonalAccessTokenRevokedEvent(Guid TokenId, Guid AccountId) : IntegrationEvent
{
    public const string EventType = "auth.pat.revoked.v1";

    public override string Type => EventType;
}

namespace JeffOps.Authentication.Abstractions.Messaging;

/// <summary>
/// A step in the life of an impersonation grant. <see cref="Stage"/> is one of <c>requested</c>, <c>approved</c>,
/// <c>started</c>, <c>denied</c>, <c>ended</c>, <c>revoked</c>, <c>expired</c>; the event type is
/// <c>auth.impersonation.{stage}.v1</c>.
/// </summary>
public sealed record ImpersonationEvent(string Stage, Guid GrantId, Guid ActorUserId, Guid TargetUserId, Guid? TargetTenantId, bool BreakGlass) : IntegrationEvent
{
    public override string Type => $"auth.impersonation.{Stage}.v1";
}

/// <summary>
/// A step in the life of a lockbox tenant-access grant; the event type is <c>auth.tenant_access.{stage}.v1</c> with the stages
/// of <see cref="ImpersonationEvent"/>.
/// </summary>
public sealed record TenantAccessEvent(string Stage, Guid GrantId, Guid ActorUserId, Guid? ActorOrganizationId, Guid TargetTenantId) : IntegrationEvent
{
    public override string Type => $"auth.tenant_access.{Stage}.v1";
}

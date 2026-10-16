namespace JeffOps.Authentication.Abstractions.Messaging;

/// <summary>
/// A step in the life of an impersonation grant. <see cref="Stage"/> is one of <c>requested</c>, <c>approved</c>,
/// <c>started</c>, <c>denied</c>, <c>ended</c>, <c>revoked</c>, <c>expired</c>; the event type is
/// <c>auth.impersonation.{stage}.v1</c>.
/// </summary>
/// <param name="Stage">The lifecycle step, for example <c>requested</c> or <c>started</c>.</param>
/// <param name="GrantId">The impersonation grant.</param>
/// <param name="ActorUserId">The user who acts as the target, for example a support engineer.</param>
/// <param name="TargetUserId">The user being impersonated.</param>
/// <param name="TargetTenantId">The target's tenant, if any.</param>
/// <param name="BreakGlass">True when the grant skips the target's consent; such grants need a reason and a dedicated permission.</param>
public sealed record ImpersonationEvent(string Stage, Guid GrantId, Guid ActorUserId, Guid TargetUserId, Guid? TargetTenantId, bool BreakGlass) : IntegrationEvent
{
    /// <summary><c>auth.impersonation.{stage}.v1</c>, with <see cref="Stage"/> filled in.</summary>
    public override string Type => $"auth.impersonation.{Stage}.v1";
}

/// <summary>
/// A step in the life of a lockbox tenant-access grant; the event type is <c>auth.tenant_access.{stage}.v1</c> with the stages
/// of <see cref="ImpersonationEvent"/>.
/// </summary>
/// <param name="Stage">The lifecycle step, for example <c>requested</c> or <c>approved</c>.</param>
/// <param name="GrantId">The tenant-access grant.</param>
/// <param name="ActorUserId">The user who asked to access the tenant.</param>
/// <param name="ActorOrganizationId">The organization the actor acts for, if any.</param>
/// <param name="TargetTenantId">The tenant being accessed, whose administrators approve or deny the request.</param>
public sealed record TenantAccessEvent(string Stage, Guid GrantId, Guid ActorUserId, Guid? ActorOrganizationId, Guid TargetTenantId) : IntegrationEvent
{
    /// <summary><c>auth.tenant_access.{stage}.v1</c>, with <see cref="Stage"/> filled in.</summary>
    public override string Type => $"auth.tenant_access.{Stage}.v1";
}

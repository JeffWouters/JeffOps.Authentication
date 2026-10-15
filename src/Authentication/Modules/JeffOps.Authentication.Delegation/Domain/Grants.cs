namespace JeffOps.Authentication.Delegation.Domain;

/// <summary>Who is impersonating: platform staff (Root) or a partner organization that manages the target's tenant.</summary>
public enum ActorKind
{
    Platform = 0,
    Partner = 1,
}

/// <summary>
/// Permission for an actor to act as a target user (support "log in as"). The target approves within the approval window;
/// break-glass (platform staff only, with a reason) skips approval and notifies the target instead.
/// </summary>
public sealed class ImpersonationGrant : DelegationGrant
{
    private ImpersonationGrant(
        Guid actorUserId, Guid? actorOrganizationId, ActorKind actorKind, Guid targetUserId, Guid? targetTenantId, bool breakGlass, string? reason,
        DateTimeOffset now, TimeSpan approvalWindow)
        : base(Guid.NewGuid(), actorUserId, actorOrganizationId, now, approvalWindow)
    {
        ActorKind = actorKind;
        TargetUserId = targetUserId;
        TargetTenantId = targetTenantId;
        BreakGlass = breakGlass;
        Reason = reason;
    }

    private ImpersonationGrant()
    {
    }

    public ActorKind ActorKind { get; private set; }

    public Guid TargetUserId { get; private set; }

    /// <summary>The tenant the target is impersonated in: their session tenant when the grant was requested.</summary>
    public Guid? TargetTenantId { get; private set; }

    public bool BreakGlass { get; private set; }

    public string? Reason { get; private set; }

    /// <summary>A request the target must approve.</summary>
    public static ImpersonationGrant Request(
        Guid actorUserId, Guid? actorOrganizationId, ActorKind actorKind, Guid targetUserId, Guid? targetTenantId, string? reason,
        DateTimeOffset now, TimeSpan approvalWindow)
    {
        if (actorUserId == targetUserId)
        {
            throw new ArgumentException("Nobody impersonates themselves.", nameof(targetUserId));
        }

        var grant = new ImpersonationGrant(actorUserId, actorOrganizationId, actorKind, targetUserId, targetTenantId, breakGlass: false, Trimmed(reason), now, approvalWindow);
        grant.Announce();
        return grant;
    }

    /// <summary>Break-glass: approved at once, for platform staff, with a mandatory reason.</summary>
    public static ImpersonationGrant BreakGlassAccess(
        Guid actorUserId, Guid? actorOrganizationId, Guid targetUserId, Guid? targetTenantId, string reason,
        DateTimeOffset now, TimeSpan sessionWindow)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        if (actorUserId == targetUserId)
        {
            throw new ArgumentException("Nobody impersonates themselves.", nameof(targetUserId));
        }

        var grant = new ImpersonationGrant(actorUserId, actorOrganizationId, ActorKind.Platform, targetUserId, targetTenantId, breakGlass: true, Trimmed(reason), now, TimeSpan.Zero);
        grant.ApproveAtCreation(now, sessionWindow);
        grant.Announce();
        return grant;
    }

    private static string? Trimmed(string? reason) =>
        string.IsNullOrWhiteSpace(reason) ? null : reason.Trim()[..Math.Min(reason.Trim().Length, 500)];
}

/// <summary>
/// Lockbox: permission for a partner's user to switch into a tenant that requires approval for every partner session. An
/// administrator of the tenant approves within the approval window.
/// </summary>
public sealed class TenantAccessGrant : DelegationGrant
{
    private TenantAccessGrant(Guid actorUserId, Guid? actorOrganizationId, Guid targetTenantId, DateTimeOffset now, TimeSpan approvalWindow)
        : base(Guid.NewGuid(), actorUserId, actorOrganizationId, now, approvalWindow) =>
        TargetTenantId = targetTenantId;

    private TenantAccessGrant()
    {
    }

    public Guid TargetTenantId { get; private set; }

    public static TenantAccessGrant Request(Guid actorUserId, Guid actorOrganizationId, Guid targetTenantId, DateTimeOffset now, TimeSpan approvalWindow)
    {
        var grant = new TenantAccessGrant(actorUserId, actorOrganizationId, targetTenantId, now, approvalWindow);
        grant.Announce();
        return grant;
    }
}

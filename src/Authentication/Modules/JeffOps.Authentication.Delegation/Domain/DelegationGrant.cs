using JeffOps.Authentication.SharedKernel.Domain;

namespace JeffOps.Authentication.Delegation.Domain;

/// <summary>The life of a delegation grant. Terminal states: Denied, Expired, Revoked, Ended.</summary>
public enum DelegationGrantStatus
{
    PendingApproval = 0,
    Approved = 1,
    Active = 2,
    Denied = 3,
    Expired = 4,
    Revoked = 5,
    Ended = 6,
}

/// <summary>Why a grant stopped.</summary>
public static class GrantEndReasons
{
    public const string Denied = "denied";
    public const string Ended = "ended";
    public const string Revoked = "revoked";
    public const string RevokedByTarget = "revoked-by-target";
    public const string Expired = "expired";
}

/// <summary>
/// Permission for an actor to obtain delegated tokens for a bounded time, after someone on the other side approved it.
/// Tokens are minted against the grant again and again (no refresh tokens), each mint re-checking <see cref="CanMint"/>, so
/// ending the grant stops access within one token lifetime.
/// </summary>
public abstract class DelegationGrant : AggregateRoot<Guid>
{
    protected DelegationGrant(Guid id, Guid actorUserId, Guid? actorOrganizationId, DateTimeOffset now, TimeSpan approvalWindow)
        : base(id)
    {
        ActorUserId = actorUserId;
        ActorOrganizationId = actorOrganizationId;
        RequestedAt = now;
        ApprovalDeadline = now + approvalWindow;
        Status = DelegationGrantStatus.PendingApproval;
    }

    /// <summary>For EF Core.</summary>
    protected DelegationGrant()
    {
    }

    public Guid ActorUserId { get; private set; }

    public Guid? ActorOrganizationId { get; private set; }

    /// <summary>Also the optimistic concurrency token: two racing transitions can't both commit.</summary>
    public DelegationGrantStatus Status { get; protected set; }

    public DateTimeOffset RequestedAt { get; private set; }

    public DateTimeOffset ApprovalDeadline { get; private set; }

    public DateTimeOffset? ApprovedAt { get; protected set; }

    public Guid? ApprovedBy { get; protected set; }

    /// <summary>When the session window closes. Set at approval.</summary>
    public DateTimeOffset? ExpiresAt { get; protected set; }

    /// <summary>The first token mint; null until the grant is used.</summary>
    public DateTimeOffset? StartedAt { get; private set; }

    /// <summary>Stamped by every terminal transition, so a stale write of an older status still can't mint.</summary>
    public DateTimeOffset? EndedAt { get; private set; }

    public string? EndedReason { get; private set; }

    public bool IsTerminal => Status is DelegationGrantStatus.Denied or DelegationGrantStatus.Expired or DelegationGrantStatus.Revoked or DelegationGrantStatus.Ended;

    /// <summary>Whether the grant is waiting for a decision that may still be made.</summary>
    public bool IsPendingAt(DateTimeOffset now) => Status == DelegationGrantStatus.PendingApproval && now <= ApprovalDeadline;

    /// <summary>Whether a token may be minted against the grant now.</summary>
    public bool CanMint(DateTimeOffset now) =>
        Status is DelegationGrantStatus.Approved or DelegationGrantStatus.Active
        && EndedAt is null
        && ExpiresAt is { } expires && now < expires;

    /// <summary>Whether the grant is live (approved and not yet over), whether or not it was used.</summary>
    public bool IsLiveAt(DateTimeOffset now) => CanMint(now);

    /// <summary>Approves a pending grant within its deadline, opening a session window of <paramref name="sessionWindow"/>.</summary>
    /// <returns>False when the grant is no longer pending or the deadline passed (then it is marked expired).</returns>
    public bool Approve(Guid approvedBy, DateTimeOffset now, TimeSpan sessionWindow)
    {
        if (Status != DelegationGrantStatus.PendingApproval)
        {
            return false;
        }

        if (now > ApprovalDeadline)
        {
            Finish(DelegationGrantStatus.Expired, GrantEndReasons.Expired, now);
            return false;
        }

        Status = DelegationGrantStatus.Approved;
        ApprovedAt = now;
        ApprovedBy = approvedBy;
        ExpiresAt = now + sessionWindow;
        Raise(new DelegationGrantApproved(this));
        return true;
    }

    public bool Deny(DateTimeOffset now)
    {
        if (Status != DelegationGrantStatus.PendingApproval)
        {
            return false;
        }

        Finish(DelegationGrantStatus.Denied, GrantEndReasons.Denied, now);
        return true;
    }

    /// <summary>Records a token mint. The first one starts the grant.</summary>
    public void RecordMint(DateTimeOffset now)
    {
        if (!CanMint(now))
        {
            throw new InvalidOperationException("The grant can't mint tokens.");
        }

        if (StartedAt is null)
        {
            StartedAt = now;
            Status = DelegationGrantStatus.Active;
            Raise(new DelegationGrantStarted(this));
        }
    }

    /// <summary>Ends a live grant normally (the actor is done, or the target ends it).</summary>
    public bool End(DateTimeOffset now)
    {
        if (Status is not (DelegationGrantStatus.Approved or DelegationGrantStatus.Active))
        {
            return false;
        }

        Finish(DelegationGrantStatus.Ended, GrantEndReasons.Ended, now);
        return true;
    }

    /// <summary>Withdraws a grant that isn't over yet, pending or live.</summary>
    public bool Revoke(DateTimeOffset now, string reason = GrantEndReasons.Revoked)
    {
        if (IsTerminal)
        {
            return false;
        }

        Finish(DelegationGrantStatus.Revoked, reason, now);
        return true;
    }

    /// <summary>Marks a grant whose decision or session window passed as expired. Used by the sweeper.</summary>
    public bool ExpireIfDue(DateTimeOffset now)
    {
        var due = (Status == DelegationGrantStatus.PendingApproval && now > ApprovalDeadline)
            || (Status is DelegationGrantStatus.Approved or DelegationGrantStatus.Active && ExpiresAt is { } expires && now >= expires);
        if (!due)
        {
            return false;
        }

        Finish(DelegationGrantStatus.Expired, GrantEndReasons.Expired, now);
        return true;
    }

    /// <summary>Approves a grant at creation (break-glass): no decision step, the window opens now.</summary>
    protected void ApproveAtCreation(DateTimeOffset now, TimeSpan sessionWindow)
    {
        Status = DelegationGrantStatus.Approved;
        ApprovedAt = now;
        ExpiresAt = now + sessionWindow;
    }

    protected void Announce() => Raise(new DelegationGrantRequested(this));

    private void Finish(DelegationGrantStatus status, string reason, DateTimeOffset now)
    {
        Status = status;
        EndedAt = now;
        EndedReason = reason;
        Raise(new DelegationGrantFinished(this, status, reason));
    }
}

public sealed record DelegationGrantRequested(DelegationGrant Grant) : IDomainEvent;

public sealed record DelegationGrantApproved(DelegationGrant Grant) : IDomainEvent;

public sealed record DelegationGrantStarted(DelegationGrant Grant) : IDomainEvent;

/// <summary>Raised when a grant reaches a terminal state: denied, expired, revoked or ended.</summary>
public sealed record DelegationGrantFinished(DelegationGrant Grant, DelegationGrantStatus Status, string Reason) : IDomainEvent;

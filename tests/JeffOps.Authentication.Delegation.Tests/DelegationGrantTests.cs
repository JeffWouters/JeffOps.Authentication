using JeffOps.Authentication.Delegation.Domain;

namespace JeffOps.Authentication.Delegation.Tests;

public sealed class DelegationGrantTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Approval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan Session = TimeSpan.FromMinutes(30);

    private static ImpersonationGrant Pending() =>
        ImpersonationGrant.Request(Guid.NewGuid(), null, ActorKind.Platform, Guid.NewGuid(), Guid.NewGuid(), null, Now, Approval);

    [Fact]
    public void A_request_cannot_mint_until_approved_and_mints_until_its_window_closes()
    {
        var grant = Pending();
        grant.CanMint(Now).ShouldBeFalse();
        grant.DomainEvents.ShouldContain(domainEvent => domainEvent is DelegationGrantRequested);

        grant.Approve(Guid.NewGuid(), Now.AddMinutes(1), Session).ShouldBeTrue();

        grant.CanMint(Now.AddMinutes(30)).ShouldBeTrue();
        grant.CanMint(Now.AddMinutes(31)).ShouldBeFalse();
    }

    [Fact]
    public void A_late_approval_expires_the_request()
    {
        var grant = Pending();

        grant.Approve(Guid.NewGuid(), Now.AddMinutes(6), Session).ShouldBeFalse();

        grant.Status.ShouldBe(DelegationGrantStatus.Expired);
        grant.EndedReason.ShouldBe(GrantEndReasons.Expired);
    }

    [Fact]
    public void The_first_mint_starts_the_grant_once()
    {
        var grant = Pending();
        grant.Approve(Guid.NewGuid(), Now, Session);
        grant.ClearDomainEvents();

        grant.RecordMint(Now.AddMinutes(1));
        grant.RecordMint(Now.AddMinutes(2));

        grant.Status.ShouldBe(DelegationGrantStatus.Active);
        grant.StartedAt.ShouldBe(Now.AddMinutes(1));
        grant.DomainEvents.OfType<DelegationGrantStarted>().Count().ShouldBe(1);
    }

    [Fact]
    public void Break_glass_starts_approved_and_announces_its_first_use()
    {
        var grant = ImpersonationGrant.BreakGlassAccess(Guid.NewGuid(), null, Guid.NewGuid(), null, "Incident 42", Now, Session);

        grant.Status.ShouldBe(DelegationGrantStatus.Approved);
        grant.CanMint(Now).ShouldBeTrue();
        grant.RecordMint(Now);
        grant.DomainEvents.ShouldContain(domainEvent => domainEvent is DelegationGrantStarted);
        Should.Throw<ArgumentException>(() => ImpersonationGrant.BreakGlassAccess(Guid.NewGuid(), null, Guid.NewGuid(), null, " ", Now, Session));
    }

    [Fact]
    public void Ending_and_revoking_are_final()
    {
        var grant = Pending();
        grant.Approve(Guid.NewGuid(), Now, Session);

        grant.Revoke(Now, GrantEndReasons.RevokedByTarget).ShouldBeTrue();

        grant.CanMint(Now).ShouldBeFalse();
        grant.End(Now).ShouldBeFalse();
        grant.Revoke(Now).ShouldBeFalse();
        grant.Approve(Guid.NewGuid(), Now, Session).ShouldBeFalse();
        grant.EndedReason.ShouldBe(GrantEndReasons.RevokedByTarget);
    }

    [Fact]
    public void Only_a_live_grant_ends_normally_but_a_pending_one_can_be_revoked()
    {
        var grant = Pending();

        grant.End(Now).ShouldBeFalse();
        grant.Revoke(Now).ShouldBeTrue();
        grant.Status.ShouldBe(DelegationGrantStatus.Revoked);
    }

    [Fact]
    public void Overdue_grants_expire()
    {
        var pending = Pending();
        var live = Pending();
        live.Approve(Guid.NewGuid(), Now, Session);

        pending.ExpireIfDue(Now.AddMinutes(1)).ShouldBeFalse();
        pending.ExpireIfDue(Now.AddMinutes(6)).ShouldBeTrue();
        live.ExpireIfDue(Now.AddMinutes(29)).ShouldBeFalse();
        live.ExpireIfDue(Now.AddMinutes(30)).ShouldBeTrue();
        live.Status.ShouldBe(DelegationGrantStatus.Expired);
    }

    [Fact]
    public void Nobody_impersonates_themselves()
    {
        var user = Guid.NewGuid();

        Should.Throw<ArgumentException>(() => ImpersonationGrant.Request(user, null, ActorKind.Platform, user, null, null, Now, Approval));
    }
}

using JeffOps.Authorization.Domain.Management;

namespace JeffOps.Authorization.Domain.Tests;

public sealed class GroupSyncStateTests
{
    [Fact]
    public void A_late_older_announcement_is_ignored()
    {
        var state = new GroupSyncState(Guid.NewGuid(), Guid.NewGuid());

        state.TryAdvance(3).ShouldBeTrue();
        state.TryAdvance(2).ShouldBeFalse("v2 arrived after v3");
        state.TryAdvance(3).ShouldBeTrue("a redelivery of the newest applies again");
        state.TryAdvance(4).ShouldBeTrue();
        state.Version.ShouldBe(4);
    }

    [Fact]
    public void Nothing_applies_after_the_group_is_deleted()
    {
        var state = new GroupSyncState(Guid.NewGuid(), Guid.NewGuid());
        state.TryAdvance(5).ShouldBeTrue();

        state.MarkDeleted();

        state.TryAdvance(6).ShouldBeFalse();
        state.TryAdvance(0).ShouldBeFalse();
    }

    [Fact]
    public void Unversioned_announcements_apply()
    {
        var state = new GroupSyncState(Guid.NewGuid(), Guid.NewGuid());
        state.TryAdvance(7).ShouldBeTrue();

        state.TryAdvance(0).ShouldBeTrue();
        state.Version.ShouldBe(7);
    }
}

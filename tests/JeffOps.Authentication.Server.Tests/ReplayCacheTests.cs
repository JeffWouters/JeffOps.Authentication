using JeffOps.Authentication.Abstractions.Replay;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

public sealed class ReplayCacheTests
{
    [Fact]
    public async Task One_time_values_count_once_across_instances_sharing_the_database()
    {
        await using var host = await TokenServerHost.StartAsync();
        var ct = TestContext.Current.CancellationToken;
        var replica = host.Services.GetRequiredService<IReplayCache>();
        replica.GetType().Name.ShouldBe("DatabaseReplayCache");

        // A second instance of the store, as another replica of the token server would have.
        var otherReplica = (IReplayCache)ActivatorUtilities.CreateInstance(host.Services, replica.GetType());
        var key = ReplayKeys.For("dpop", Guid.NewGuid().ToString());
        var expires = host.Time.GetUtcNow().AddMinutes(10);

        var attempts = await Task.WhenAll(Enumerable.Range(0, 8).Select(index =>
            (index % 2 == 0 ? replica : otherReplica).TryAddAsync(key, expires, ct).AsTask()));
        attempts.Count(admitted => admitted).ShouldBe(1);

        // Once expired, the key can be used again.
        host.Time.Advance(TimeSpan.FromMinutes(11));
        (await otherReplica.TryAddAsync(key, host.Time.GetUtcNow().AddMinutes(10), ct)).ShouldBeTrue();
    }
}

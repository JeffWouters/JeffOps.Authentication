using JeffOps.Authentication.Domain.Keys;
using JeffOps.Authentication.Infrastructure.Keys;
using JeffOps.Authentication.Infrastructure.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>Token keys shared by several instances of the token server (security review M12).</summary>
public sealed class KeyStoreTests
{
    [Fact]
    public async Task Another_instance_s_rotation_is_picked_up_at_the_next_check()
    {
        await using var server = await TokenServerHost.StartAsync();
        server.Services.GetRequiredService<DatabaseKeyStore>().GetSigningKeys().ShouldNotBeEmpty();
        var other = ActivatorUtilities.CreateInstance<DatabaseKeyStore>(server.Services);
        var otherRotation = ActivatorUtilities.CreateInstance<KeyRotationService>(server.Services, other);
        other.GetSigningKeys().Count.ShouldBe(1);

        server.Time.Advance(TimeSpan.FromDays(31));
        await server.Services.GetServices<Microsoft.Extensions.Hosting.IHostedService>().OfType<KeyRotationService>().Single()
            .RotateOnceAsync(TestContext.Current.CancellationToken);
        other.GetSigningKeys().Count.ShouldBe(1, "the other instance hasn't looked yet");

        // Its own check finds nothing to rotate, but storage holds keys it hasn't loaded: it loads them.
        await otherRotation.RotateOnceAsync(TestContext.Current.CancellationToken);
        other.GetSigningKeys().Count.ShouldBe(2);
        (await ActiveKeysAsync(server)).Count(key => key.Use == KeyUse.Signing).ShouldBe(2, "one new key, not one per instance");
    }

    [Fact]
    public async Task An_instance_with_another_key_ring_retires_nothing_and_refuses_to_start_new_keys()
    {
        await using var server = await TokenServerHost.StartAsync();
        server.Services.GetRequiredService<DatabaseKeyStore>().GetSigningKeys().ShouldNotBeEmpty();
        var before = await ActiveKeysAsync(server);

        var misconfigured = ActivatorUtilities.CreateInstance<DatabaseKeyStore>(server.Services, new EphemeralDataProtectionProvider());
        Should.Throw<InvalidOperationException>(() => misconfigured.GetSigningKeys());

        (await ActiveKeysAsync(server)).Select(key => key.KeyId).ShouldBe(before.Select(key => key.KeyId), ignoreOrder: true);
    }

    [Fact]
    public async Task Instances_starting_on_an_empty_store_agree_on_one_key_of_each_kind()
    {
        await using var server = await TokenServerHost.StartAsync();
        await using (var scope = server.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>().StoredKeys.ExecuteDeleteAsync(TestContext.Current.CancellationToken);
        }

        var instances = Enumerable.Range(0, 6).Select(_ => ActivatorUtilities.CreateInstance<DatabaseKeyStore>(server.Services)).ToList();
        await Task.WhenAll(instances.Select(instance => Task.Run(() => instance.GetEncryptionKeys(), TestContext.Current.CancellationToken)));

        var stored = await ActiveKeysAsync(server);
        stored.Count(key => key.Use == KeyUse.Signing).ShouldBe(1);
        stored.Count(key => key.Use == KeyUse.Encryption).ShouldBe(1);
        instances.Select(instance => instance.GetSigningKeys().Single().KeyId).Distinct().ShouldHaveSingleItem();
    }

    private static async Task<List<StoredKey>> ActiveKeysAsync(TokenServerHost server)
    {
        await using var scope = server.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>().StoredKeys
            .Where(key => key.RetiredAt == null).ToListAsync(TestContext.Current.CancellationToken);
    }
}

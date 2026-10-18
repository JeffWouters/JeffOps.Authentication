using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>Clients are read from a minute-old snapshot; a change still takes effect, at once here and within a minute elsewhere.</summary>
public sealed class ClientSnapshotTests
{
    private const string NewSecret = "a-new-secret-for-the-reports-service-0123456789";

    [Fact]
    public async Task A_secret_changed_through_the_store_takes_effect_at_once()
    {
        await using var host = await TokenServerHost.StartAsync();
        (await host.ClientCredentialsAsync()).Status.ShouldBe(HttpStatusCode.OK);

        await ChangeSecretAsync(host);

        (await host.ClientCredentialsAsync()).Status.ShouldNotBe(HttpStatusCode.OK, "the old secret");
        (await host.ClientCredentialsAsync(secret: NewSecret)).Status.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_client_changed_by_another_instance_is_read_again_within_a_minute()
    {
        await using var host = await TokenServerHost.StartAsync();
        (await host.ClientCredentialsAsync()).Status.ShouldBe(HttpStatusCode.OK);

        // Another instance changes the secret in the shared database; this one still has its snapshot.
        await ChangeSecretInDatabaseOnlyAsync(host);
        (await host.ClientCredentialsAsync()).Status.ShouldBe(HttpStatusCode.OK, "within the snapshot's minute, the old secret still works here");

        host.Time.Advance(TimeSpan.FromSeconds(61));
        (await host.ClientCredentialsAsync()).Status.ShouldNotBe(HttpStatusCode.OK, "after it, the client is read again");
        (await host.ClientCredentialsAsync(secret: NewSecret)).Status.ShouldBe(HttpStatusCode.OK);
    }

    private static async Task ChangeSecretAsync(TokenServerHost host)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var client = (await applications.FindByClientIdAsync(TokenServerHost.ServiceClient, TestContext.Current.CancellationToken))!;
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, client, TestContext.Current.CancellationToken);
        descriptor.ClientSecret = NewSecret;
        await applications.UpdateAsync(client, descriptor, TestContext.Current.CancellationToken);
    }

    /// <summary>What another instance's change looks like from here: the row changes, this instance's store isn't involved.</summary>
    private static async Task ChangeSecretInDatabaseOnlyAsync(TokenServerHost host)
    {
        // Hash the new secret as OpenIddict stores it, in a throwaway client, then copy the hash onto the real row directly.
        await using var scope = host.Services.CreateAsyncScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var throwawayId = "throwaway-" + Guid.NewGuid().ToString("N");
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = throwawayId,
            ClientSecret = NewSecret,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
        }, TestContext.Current.CancellationToken);

        var db = scope.ServiceProvider.GetRequiredService<Infrastructure.Persistence.AuthenticationDbContext>();
        var hash = await db.Set<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication>()
            .Where(application => application.ClientId == throwawayId).Select(application => application.ClientSecret).SingleAsync(TestContext.Current.CancellationToken);
        var updated = await db.Set<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication>()
            .Where(application => application.ClientId == TokenServerHost.ServiceClient)
            .ExecuteUpdateAsync(set => set.SetProperty(application => application.ClientSecret, hash), TestContext.Current.CancellationToken);
        updated.ShouldBe(1);
    }
}

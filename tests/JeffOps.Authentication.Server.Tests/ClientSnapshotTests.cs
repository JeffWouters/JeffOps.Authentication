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

    [Fact]
    public async Task A_client_no_longer_configured_is_refused_and_deleted_at_startup()
    {
        await using var host = await TokenServerHost.StartAsync();
        var ct = TestContext.Current.CancellationToken;

        // A client from an earlier configuration, still in the database.
        await using (var scope = host.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "retired",
                ClientSecret = NewSecret,
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                Permissions = { OpenIddictConstants.Permissions.Endpoints.Token, OpenIddictConstants.Permissions.GrantTypes.ClientCredentials },
            }, ct);
        }

        (await host.TokenAsync(new() { ["grant_type"] = "client_credentials", ["client_id"] = "retired", ["client_secret"] = NewSecret }))
            .Error.ShouldBe("invalid_client");

        // The next startup deletes it.
        await host.Services.GetServices<Microsoft.Extensions.Hosting.IHostedService>().Single(service => service.GetType().Name == "AuthenticationStartup").StartAsync(ct);
        await using var check = host.Services.CreateAsyncScope();
        var db = check.ServiceProvider.GetRequiredService<Infrastructure.Persistence.AuthenticationDbContext>();
        (await db.Set<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication>().AnyAsync(application => application.ClientId == "retired", ct)).ShouldBeFalse();
        (await host.ClientCredentialsAsync()).Status.ShouldBe(HttpStatusCode.OK, "configured clients stay");
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

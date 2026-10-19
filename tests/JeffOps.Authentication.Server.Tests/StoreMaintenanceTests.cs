using System.Net;
using JeffOps.Authentication.Infrastructure.Persistence;
using JeffOps.Authentication.Infrastructure.Server;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.EntityFrameworkCore.Models;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Server.Tests;

public sealed class StoreMaintenanceTests
{
    [Fact]
    public async Task Spent_tokens_are_pruned_once_older_than_the_retention()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var tokens = await server.SignInAsync(account.Id);
        (await server.RefreshAsync(tokens.RefreshToken!)).Status.ShouldBe(HttpStatusCode.OK);
        var maintenance = Maintenance(server);

        await maintenance.PruneAsync(TestContext.Current.CancellationToken);
        (await RedeemedAsync(server)).ShouldBeGreaterThan(0, "the code and the first refresh token are redeemed, and recent");

        server.Time.Advance(TimeSpan.FromDays(15));
        await maintenance.PruneAsync(TestContext.Current.CancellationToken);
        (await RedeemedAsync(server)).ShouldBe(0);
    }

    [Fact]
    public async Task A_redeemed_refresh_token_is_kept_while_it_could_still_be_presented()
    {
        // A retention shorter than the session is raised to it: reuse of a refresh token is still recognised.
        await using var server = await TokenServerHost.StartAsync(new() { ["JeffOps:TokenServer:PruneAfter"] = "00:01:00" });
        var account = await server.CreateAccountAsync();
        var tokens = await server.SignInAsync(account.Id);
        (await server.RefreshAsync(tokens.RefreshToken!)).Status.ShouldBe(HttpStatusCode.OK);

        server.Time.Advance(TimeSpan.FromHours(2));
        await Maintenance(server).PruneAsync(TestContext.Current.CancellationToken);

        (await RedeemedAsync(server)).ShouldBeGreaterThan(0);
        (await server.RefreshAsync(tokens.RefreshToken!)).Error.ShouldBe("invalid_grant");
    }

    private static StoreMaintenance Maintenance(TokenServerHost server) =>
        server.Services.GetServices<IHostedService>().OfType<StoreMaintenance>().Single();

    private static async Task<int> RedeemedAsync(TokenServerHost server)
    {
        await using var scope = server.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>().Set<OpenIddictEntityFrameworkCoreToken>()
            .CountAsync(token => token.Status == Statuses.Redeemed, TestContext.Current.CancellationToken);
    }
}

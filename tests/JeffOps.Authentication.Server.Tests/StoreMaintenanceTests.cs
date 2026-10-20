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

    [Fact]
    public async Task Expired_replay_entries_and_old_sessions_are_deleted_in_batches_and_live_ones_kept()
    {
        await using var server = await TokenServerHost.StartAsync();
        var ct = TestContext.Current.CancellationToken;
        var now = server.Time.GetUtcNow();
        var past = now.AddMinutes(-1).ToUnixTimeMilliseconds();
        var future = now.AddMinutes(5).ToUnixTimeMilliseconds();
        var longAgo = (now - TimeSpan.FromHours(9)).ToUnixTimeMilliseconds(); // the session lifetime is 8 hours
        await using (var scope = server.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>();
            db.ReplayEntries.AddRange(Enumerable.Range(0, 12_001).Select(index => new ReplayEntry($"expired-{index}", past)));
            db.ReplayEntries.Add(new ReplayEntry("live", future));
            db.ExternalSessions.Add(new ExternalSessionEntry("expired-session", "provider", null, Guid.NewGuid(), past));
            db.ExternalSessions.Add(new ExternalSessionEntry("live-session", "provider", null, Guid.NewGuid(), future));
            db.EndedSessions.Add(new EndedSession("ended-long-ago", Guid.NewGuid(), longAgo));
            db.EndedSessions.Add(new EndedSession("ended-recently", Guid.NewGuid(), past));
            await db.SaveChangesAsync(ct);
        }

        await Maintenance(server).SweepAsync(ct);

        await using (var scope = server.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>();
            (await db.ReplayEntries.Select(entry => entry.Key).ToListAsync(ct)).ShouldBe(["live"], "more than two batches of expired entries");
            (await db.ExternalSessions.Select(entry => entry.SessionId).ToListAsync(ct)).ShouldBe(["live-session"]);
            (await db.EndedSessions.Select(entry => entry.SessionId).ToListAsync(ct)).ShouldBe(["ended-recently"], "its tokens could still be refreshed");
        }
    }

    [Fact]
    public async Task Ended_sessions_and_spent_refresh_tokens_are_kept_as_long_as_any_client_s_session_lasts()
    {
        // One client's sessions last 24 hours: an ended session must still count, and a spent refresh token still be
        // recognised, after the server's own 8.
        await using var server = await TokenServerHost.StartAsync(new()
        {
            ["JeffOps:TokenServer:PruneAfter"] = "00:01:00",
            ["JeffOps:TokenServer:Clients:0:SessionLifetime"] = "1.00:00:00",
        });
        var ct = TestContext.Current.CancellationToken;
        var account = await server.CreateAccountAsync();
        var tokens = await server.SignInAsync(account.Id);
        (await server.RefreshAsync(tokens.RefreshToken!)).Status.ShouldBe(HttpStatusCode.OK);
        var endedAt = (server.Time.GetUtcNow() - TimeSpan.FromHours(9)).ToUnixTimeMilliseconds();
        await using (var scope = server.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>();
            db.EndedSessions.Add(new EndedSession("ended-nine-hours-ago", Guid.NewGuid(), endedAt));
            await db.SaveChangesAsync(ct);
        }

        server.Time.Advance(TimeSpan.FromHours(9));
        await Maintenance(server).SweepAsync(ct);
        await Maintenance(server).PruneAsync(ct);

        await using (var scope = server.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>();
            (await db.EndedSessions.Select(entry => entry.SessionId).ToListAsync(ct)).ShouldContain("ended-nine-hours-ago");
        }

        (await RedeemedAsync(server)).ShouldBeGreaterThan(0);
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

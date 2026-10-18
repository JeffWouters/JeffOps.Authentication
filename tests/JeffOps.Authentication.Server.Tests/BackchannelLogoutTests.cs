using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using JeffOps.Authentication.Application.Features.Sessions.EndSession;
using JeffOps.Authentication.SharedKernel.Handlers;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>Back-channel logout to clients when a session ends (OpenID Connect Back-Channel Logout 1.0).</summary>
public sealed class BackchannelLogoutTests
{
    [Fact]
    public async Task Clients_are_told_at_once_and_a_hanging_one_doesn_t_hold_up_signing_out()
    {
        var clients = new SlowClients();
        await using var host = await TokenServerHost.StartAsync(
            new()
            {
                ["JeffOps:TokenServer:BackchannelLogoutTimeout"] = "00:00:02",
                ["JeffOps:TokenServer:Clients:0:BackchannelLogoutUri"] = "https://a.test/logout",
                ["JeffOps:TokenServer:Clients:1:BackchannelLogoutUri"] = "https://b.test/logout",
                ["JeffOps:TokenServer:Clients:2:BackchannelLogoutUri"] = "https://hangs.test/logout",
            },
            configure: builder => builder.Services.AddHttpClient("JeffOps.BackchannelLogout").ConfigurePrimaryHttpMessageHandler(() => clients));
        var account = await host.CreateAccountAsync();

        var elapsed = Stopwatch.StartNew();
        await using (var scope = host.Services.CreateAsyncScope())
        {
            (await scope.ServiceProvider.GetRequiredService<ICommandHandler<EndSessionCommand>>()
                .HandleAsync(new EndSessionCommand(account.Id, "session-1"), TestContext.Current.CancellationToken)).IsSuccess.ShouldBeTrue();
        }

        elapsed.Stop();
        clients.Told.ShouldBe(["a.test", "b.test"], ignoreOrder: true);
        elapsed.Elapsed.ShouldBeLessThan(TimeSpan.FromSeconds(6), "the clients are told together, and the hanging one only until the timeout");
        TestContext.Current.SendDiagnosticMessage($"Signing out with two 100 ms clients and one hanging: {elapsed.ElapsedMilliseconds} ms");
    }

    /// <summary>Two clients that answer after 100 ms, and one that never answers.</summary>
    private sealed class SlowClients : HttpMessageHandler
    {
        public ConcurrentBag<string> Told { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var host = request.RequestUri!.Host;
            await Task.Delay(host == "hangs.test" ? Timeout.InfiniteTimeSpan : TimeSpan.FromMilliseconds(100), cancellationToken);
            Told.Add(host);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }
}

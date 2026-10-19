using System.Net;
using JeffOps.Authentication.Abstractions.RateLimiting;
using Microsoft.Extensions.Time.Testing;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>Rate limits of the protocol endpoints and the limiter itself (security review M8, decision D28).</summary>
public sealed class RateLimitTests
{
    [Fact]
    public async Task Protocol_requests_naming_one_client_are_rate_limited_before_the_client_is_checked()
    {
        await using var host = await TokenServerHost.StartAsync(new() { ["JeffOps:RateLimiting:ProtocolPerClient:PermitLimit"] = "2" });

        (await host.ClientCredentialsAsync()).Status.ShouldBe(HttpStatusCode.OK);
        (await host.TokenAsync(new() { ["grant_type"] = "client_credentials", ["client_id"] = TokenServerHost.ServiceClient, ["client_secret"] = "wrong" }))
            .Error.ShouldBe("invalid_client");

        var limited = await host.ClientCredentialsAsync();
        limited.Status.ShouldBe(HttpStatusCode.TooManyRequests);
        limited.Error.ShouldBe("temporarily_unavailable");

        host.Time.Advance(TimeSpan.FromMinutes(1));
        (await host.ClientCredentialsAsync()).Status.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Discovery_isn_t_limited_and_the_limits_can_be_turned_off()
    {
        await using var host = await TokenServerHost.StartAsync(new()
        {
            ["JeffOps:RateLimiting:ProtocolPerAddress:PermitLimit"] = "1",
        });
        for (var i = 0; i < 3; i++)
        {
            (await host.Client.GetAsync(new Uri(".well-known/openid-configuration", UriKind.Relative), TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);
        }

        await using var off = await TokenServerHost.StartAsync(new()
        {
            ["JeffOps:RateLimiting:Enabled"] = "false",
            ["JeffOps:RateLimiting:ProtocolPerAddress:PermitLimit"] = "1",
        });
        (await off.ClientCredentialsAsync()).Status.ShouldBe(HttpStatusCode.OK);
        (await off.ClientCredentialsAsync()).Status.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public void Windows_are_fixed_and_partitions_count_apart()
    {
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 10, 19, 12, 0, 30, TimeSpan.Zero));
        var limiter = new RequestRateLimiter(time);
        var limit = new RateLimit(2, TimeSpan.FromMinutes(1));

        limiter.TryAcquire(limit, "a", out _).ShouldBeTrue();
        limiter.TryAcquire(limit, "a", out _).ShouldBeTrue();
        limiter.TryAcquire(limit, "a", out var wait).ShouldBeFalse();
        wait.ShouldBe(TimeSpan.FromSeconds(30), "until the window ends");
        limiter.TryAcquire(limit, "b", out _).ShouldBeTrue("another partition");

        time.Advance(TimeSpan.FromSeconds(30));
        limiter.TryAcquire(limit, "a", out _).ShouldBeTrue("a new window");
    }
}

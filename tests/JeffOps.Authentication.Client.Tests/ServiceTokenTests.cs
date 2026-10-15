using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using JeffOps.Authentication.Client.Access;
using JeffOps.Authentication.Client.DependencyInjection;
using JeffOps.Authentication.Client.ServiceTokens;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace JeffOps.Authentication.Client.Tests;

public sealed class ServiceTokenTests
{
    private static readonly Dictionary<string, string?> Settings = new()
    {
        ["JeffOps:ServiceToken:TokenEndpoint"] = "https://issuer.test/connect/token",
        ["JeffOps:ServiceToken:ClientId"] = "svc-reports",
        ["JeffOps:ServiceToken:ClientSecret"] = "s3cret",
        ["JeffOps:ServiceToken:Scope"] = "api",
    };

    private static (ServiceProvider Provider, TokenEndpoint Endpoint, FakeTimeProvider Time) Build(Dictionary<string, string?>? settings = null)
    {
        var endpoint = new TokenEndpoint();
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 10, 15, 12, 0, 0, TimeSpan.Zero));
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(time);
        services.AddJeffOpsServiceTokens(new ConfigurationBuilder().AddInMemoryCollection(settings ?? Settings).Build());
        services.AddHttpClient(ServiceTokenProvider.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => endpoint);
        return (services.BuildServiceProvider(), endpoint, time);
    }

    [Fact]
    public async Task The_client_credentials_request_carries_the_configured_identity()
    {
        var (provider, endpoint, _) = Build();
        await using var _ = provider;

        var token = await provider.GetRequiredService<ServiceTokenProvider>().GetTokenAsync(TestContext.Current.CancellationToken);

        token.ShouldBe("token-1");
        endpoint.LastForm.ShouldContain("grant_type=client_credentials");
        endpoint.LastForm.ShouldContain("client_id=svc-reports");
        endpoint.LastForm.ShouldContain("scope=api");
    }

    [Fact]
    public async Task A_token_is_reused_until_shortly_before_it_expires()
    {
        var (provider, endpoint, time) = Build();
        await using var _ = provider;
        var tokens = provider.GetRequiredService<ServiceTokenProvider>();

        await tokens.GetTokenAsync(TestContext.Current.CancellationToken);
        time.Advance(TimeSpan.FromMinutes(3));
        (await tokens.GetTokenAsync(TestContext.Current.CancellationToken)).ShouldBe("token-1");

        time.Advance(TimeSpan.FromMinutes(1.5)); // expires_in is 300 s; refresh 60 s early
        (await tokens.GetTokenAsync(TestContext.Current.CancellationToken)).ShouldBe("token-2");
        endpoint.Calls.ShouldBe(2);
    }

    [Fact]
    public async Task Concurrent_callers_share_one_request()
    {
        var (provider, endpoint, _) = Build();
        await using var _ = provider;
        var tokens = provider.GetRequiredService<ServiceTokenProvider>();

        await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => tokens.GetTokenAsync(TestContext.Current.CancellationToken)));

        endpoint.Calls.ShouldBe(1);
    }

    [Fact]
    public async Task A_refused_request_throws_without_leaking_the_secret()
    {
        var (provider, endpoint, _) = Build();
        await using var _ = provider;
        endpoint.Status = HttpStatusCode.Unauthorized;

        var exception = await Should.ThrowAsync<HttpRequestException>(() =>
            provider.GetRequiredService<ServiceTokenProvider>().GetTokenAsync(TestContext.Current.CancellationToken));

        exception.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        exception.Message.ShouldNotContain("s3cret");
    }

    [Fact]
    public void Missing_credentials_fail_validation_instead_of_using_a_default()
    {
        var (provider, _, _) = Build(new Dictionary<string, string?> { ["JeffOps:ServiceToken:TokenEndpoint"] = "https://issuer.test/token" });
        using var _ = provider;

        Should.Throw<OptionsValidationException>(() => provider.GetRequiredService<IOptions<ServiceTokenOptions>>().Value);
    }

    [Fact]
    public async Task The_handler_adds_the_token_only_when_no_authorization_is_present()
    {
        var (provider, _, _) = Build();
        await using var _ = provider;
        var downstream = new RecordingHandler();
        using var client = new HttpClient(new ServiceTokenHandler(provider.GetRequiredService<ServiceTokenProvider>()) { InnerHandler = downstream });

        await client.GetAsync(new Uri("https://callee.test/a"), TestContext.Current.CancellationToken);
        downstream.LastAuthorization.ShouldBe("Bearer token-1");

        using var explicitRequest = new HttpRequestMessage(HttpMethod.Get, "https://callee.test/b");
        explicitRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "user-token");
        await client.SendAsync(explicitRequest, TestContext.Current.CancellationToken);
        downstream.LastAuthorization.ShouldBe("Bearer user-token");
    }

    [Fact]
    public async Task Propagation_sends_the_callers_tenants()
    {
        var home = Guid.NewGuid();
        var acting = Guid.NewGuid();
        var accessor = new HttpContextAccessor
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(
                    [new Claim("sub", Guid.NewGuid().ToString()), new Claim("tid", home.ToString()), new Claim("act_tid", acting.ToString())], "test")),
            },
        };
        var downstream = new RecordingHandler();
        using var client = new HttpClient(new AccessContextPropagationHandler(
            accessor,
            Abstractions.Claims.ClaimNames.Default,
            Options.Create(new AuthenticationClientOptions())) { InnerHandler = downstream });

        await client.GetAsync(new Uri("https://callee.test/"), TestContext.Current.CancellationToken);

        downstream.LastHeaders!.GetValues("X-Tenant-Id").ShouldBe([home.ToString()]);
        downstream.LastHeaders.GetValues("X-Acting-Tenant-Id").ShouldBe([acting.ToString()]);
    }

    private sealed class TokenEndpoint : HttpMessageHandler
    {
        private int _calls;

        public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;

        public int Calls => Volatile.Read(ref _calls);

        public string LastForm { get; private set; } = "";

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var call = Interlocked.Increment(ref _calls);
            LastForm = await request.Content!.ReadAsStringAsync(cancellationToken);
            await Task.Delay(10, cancellationToken);
            return new HttpResponseMessage(Status)
            {
                Content = new StringContent($$"""{"access_token":"token-{{call}}","expires_in":300}""", Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public string? LastAuthorization { get; private set; }

        public HttpRequestHeaders? LastHeaders { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastAuthorization = request.Headers.Authorization?.ToString();
            LastHeaders = request.Headers;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}

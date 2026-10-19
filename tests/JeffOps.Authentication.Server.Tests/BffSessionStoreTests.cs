using System.Security.Claims;
using JeffOps.Authentication.Bff;
using JeffOps.Authentication.Bff.Sessions;
using JeffOps.Authentication.Bff.Yarp;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace JeffOps.Authentication.Server.Tests;

public sealed class BffSessionStoreTests
{
    [Fact]
    public async Task A_logout_naming_one_session_ends_it_and_what_was_derived_from_it_only()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var store = new BffSessionStore(
            new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())),
            new EphemeralDataProtectionProvider(),
            Options.Create(new BffOptions()),
            time);
        var ct = TestContext.Current.CancellationToken;
        var ends = time.GetUtcNow().AddHours(1);

        var laptop = await store.CreateAsync(new BffSession("ada", "at-1", "rt-1", IdToken("ada", "laptop-sid"), ends, ends), ct);
        var phone = await store.CreateAsync(new BffSession("ada", "at-2", "rt-2", IdToken("ada", "phone-sid"), ends, ends), ct);
        var impersonating = await store.CreateAsync(
            new BffSession("ada", "at-3", null, null, ends, ends) { Kind = "impersonation", OwnerKey = BffSessionStore.KeyFor(laptop) }, ct);

        (await store.DeleteSessionAsync("ada", "laptop-sid", ct)).ShouldBe(2);

        (await store.GetAsync(laptop, ct)).ShouldBeNull();
        (await store.GetAsync(impersonating, ct)).ShouldBeNull("derived from the ended session");
        (await store.GetAsync(phone, ct)).ShouldNotBeNull("the user's other session continues");
    }

    [Fact]
    public async Task A_session_copied_under_another_session_s_key_doesn_t_decrypt_there()
    {
        var time = new FakeTimeProvider(DateTimeOffset.UtcNow);
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var store = new BffSessionStore(cache, new EphemeralDataProtectionProvider(), Options.Create(new BffOptions()), time);
        var ct = TestContext.Current.CancellationToken;
        var ends = time.GetUtcNow().AddHours(1);
        var victim = await store.CreateAsync(new BffSession("ada", "victim-token", "rt-1", null, ends, ends), ct);
        var attacker = await store.CreateAsync(new BffSession("mallory", "attacker-token", "rt-2", null, ends, ends), ct);

        // Someone who can write to the shared cache puts the victim's encrypted session under their own session's key.
        await cache.SetStringAsync(BffSessionStore.KeyFor(attacker), (await cache.GetStringAsync(BffSessionStore.KeyFor(victim), ct))!, ct);

        (await store.GetAsync(attacker, ct)).ShouldBeNull();
        (await store.GetAsync(victim, ct)).ShouldNotBeNull().AccessToken.ShouldBe("victim-token");
    }

    [Fact]
    public async Task An_exchanged_token_copied_under_another_pat_s_key_doesn_t_decrypt_there()
    {
        var cache = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        var tokenServer = new TokenEndpoint();
        PatExchanger Exchanger() => new(
            new Clients(tokenServer),
            cache,
            new MemoryCache(Options.Create(new MemoryCacheOptions())),   // a fresh instance each time: only the shared cache is shared
            Provider,
            Options.Create(new PatExchangeOptions { TokenEndpoint = new Uri("https://login.test/connect/token"), ClientId = "bff", ClientSecret = "secret" }),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<PatExchanger>.Instance);
        var ct = TestContext.Current.CancellationToken;

        (await Exchanger().ExchangeAsync("pat_victim", ct)).AccessToken.ShouldBe("jwt-for-pat_victim");
        (await Exchanger().ExchangeAsync("pat_attacker", ct)).AccessToken.ShouldBe("jwt-for-pat_attacker");
        static string KeyOf(string pat) => "jeffops:pat:" + Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(pat)));
        await cache.SetStringAsync(KeyOf("pat_attacker"), (await cache.GetStringAsync(KeyOf("pat_victim"), ct))!, ct);

        // The copied value isn't the attacker's: the PAT is exchanged again, for its own token.
        (await Exchanger().ExchangeAsync("pat_attacker", ct)).AccessToken.ShouldBe("jwt-for-pat_attacker");
        tokenServer.Exchanges.ShouldBe(3);
    }

    private static readonly IDataProtectionProvider Provider = new EphemeralDataProtectionProvider();

    /// <summary>A token endpoint that exchanges any PAT for a token naming it.</summary>
    private sealed class TokenEndpoint : HttpMessageHandler
    {
        private int _exchanges;

        public int Exchanges => Volatile.Read(ref _exchanges);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _exchanges);
            var form = System.Web.HttpUtility.ParseQueryString(await request.Content!.ReadAsStringAsync(cancellationToken));
            return new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = System.Net.Http.Json.JsonContent.Create(new Dictionary<string, object> { ["access_token"] = "jwt-for-" + form["pat"], ["expires_in"] = 300 }),
            };
        }
    }

    private sealed class Clients(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private static string IdToken(string subject, string sessionId) => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity([new Claim("sub", subject), new Claim("sid", sessionId)]),
    });
}

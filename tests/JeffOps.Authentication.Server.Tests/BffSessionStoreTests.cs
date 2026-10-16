using System.Security.Claims;
using JeffOps.Authentication.Bff;
using JeffOps.Authentication.Bff.Sessions;
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

    private static string IdToken(string subject, string sessionId) => new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity([new Claim("sub", subject), new Claim("sid", sessionId)]),
    });
}

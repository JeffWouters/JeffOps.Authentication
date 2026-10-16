using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Keys;
using JeffOps.Authentication.Domain.PersonalAccessTokens;
using JeffOps.Authentication.Domain.Sessions;

namespace JeffOps.Authentication.Domain.Tests;

public sealed class AccountTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Registering_normalizes_the_email_and_raises_an_event()
    {
        var account = Account.Register("  Ada@Example.COM ", "Ada", emailVerified: false, Now);

        account.Email.ShouldBe("ada@example.com");
        account.CanAuthenticate.ShouldBeTrue();
        account.DomainEvents.ShouldHaveSingleItem().ShouldBeOfType<AccountRegistered>();
    }

    [Fact]
    public void External_logins_link_on_issuer_and_subject_normalized()
    {
        var key = new ExternalLoginKey("https://Login.Example/tenant/", "ABC-123");
        var account = Account.RegisterExternal("ada@example.com", "Ada", key, "entra", Now);

        account.EmailVerified.ShouldBeTrue();
        account.ExternalLogins.ShouldHaveSingleItem().Key.ShouldBe(new ExternalLoginKey("https://login.example/tenant", "abc-123"));

        account.LinkExternalLogin(new ExternalLoginKey("https://login.example/tenant", "abc-123"), "entra", Now);
        account.ExternalLogins.Count.ShouldBe(1, "linking the same key twice is a no-op");
    }

    [Fact]
    public void Disabling_and_enabling_report_whether_anything_changed()
    {
        var account = Account.Register("ada@example.com", "Ada", true, Now);
        account.ClearDomainEvents();

        account.Disable(Now).ShouldBeTrue();
        account.Disable(Now).ShouldBeFalse();
        account.CanAuthenticate.ShouldBeFalse();
        account.Enable(Now).ShouldBeTrue();
        account.Enable(Now).ShouldBeFalse();
        account.DomainEvents.Count.ShouldBe(2);
    }

    [Fact]
    public void Revoking_sessions_ends_those_signed_in_before_it_to_the_second()
    {
        var account = Account.Register("ada@example.com", "Ada", true, Now);
        account.IsSessionRevoked(Now.AddDays(-1)).ShouldBeFalse();

        account.RevokeSessions(Now.AddMilliseconds(500), "password_changed");

        account.IsSessionRevoked(Now.AddSeconds(-1)).ShouldBeTrue();
        account.IsSessionRevoked(Now).ShouldBeFalse("a sign-in in the same second (auth_time has second precision) stays valid");
        account.IsSessionRevoked(Now.AddSeconds(1)).ShouldBeFalse();
        account.DomainEvents.OfType<AccountSessionsRevoked>().ShouldHaveSingleItem().Reason.ShouldBe("password_changed");
    }
}

public sealed class PersonalAccessTokenTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void A_token_stores_only_the_hash_of_its_secret()
    {
        var (token, secret) = PersonalAccessToken.Create(Guid.NewGuid(), "ci", null, [], false, TimeSpan.FromDays(30), "pat_", Now);

        secret.ShouldStartWith("pat_");
        secret.Length.ShouldBeGreaterThan(40);
        token.SecretHash.ShouldBe(PatSecret.Hash(secret));
        token.SecretHash.ShouldNotContain(secret);
    }

    [Fact]
    public void Lowering_the_maximum_lifetime_shortens_existing_tokens()
    {
        var (token, _) = PersonalAccessToken.Create(Guid.NewGuid(), "ci", null, [], false, TimeSpan.FromDays(90), "pat_", Now);

        token.EffectiveExpiresAt(TimeSpan.FromDays(90)).ShouldBe(Now.AddDays(90));
        token.EffectiveExpiresAt(TimeSpan.FromDays(30)).ShouldBe(Now.AddDays(30));
        token.IsActive(Now.AddDays(31), TimeSpan.FromDays(30)).ShouldBeFalse();
        token.IsActive(Now.AddDays(31), TimeSpan.FromDays(90)).ShouldBeTrue();
    }

    [Fact]
    public void A_revoked_token_is_inactive_and_revoking_twice_reports_no_change()
    {
        var (token, _) = PersonalAccessToken.Create(Guid.NewGuid(), "ci", null, [], false, TimeSpan.FromDays(30), "pat_", Now);

        token.Revoke(Now).ShouldBeTrue();
        token.Revoke(Now).ShouldBeFalse();
        token.IsActive(Now, TimeSpan.FromDays(90)).ShouldBeFalse();
    }

    [Fact]
    public void The_ceiling_round_trips_and_ignores_blanks() =>
        PersonalAccessToken.Create(Guid.NewGuid(), "ci", null, ["a.b.read", " ", "c.*"], false, TimeSpan.FromDays(1), "pat_", Now)
            .Token.Ceiling().ShouldBe(["a.b.read", "c.*"]);

    [Fact]
    public void A_token_must_expire() =>
        Should.Throw<ArgumentOutOfRangeException>(() =>
            PersonalAccessToken.Create(Guid.NewGuid(), "ci", null, [], false, TimeSpan.Zero, "pat_", Now));
}

public sealed class KeyRotationTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Interval = TimeSpan.FromDays(30);
    private static readonly TimeSpan Overlap = TimeSpan.FromDays(7);

    private static StoredKey Key(DateTimeOffset created, TimeSpan delay) => StoredKey.Create(KeyUse.Signing, "protected", created, delay);

    [Fact]
    public void An_empty_store_creates_a_key() => KeyRotation.Plan([], Start, Interval, Overlap).CreateNew.ShouldBeTrue();

    [Fact]
    public void A_young_key_is_kept() =>
        KeyRotation.Plan([Key(Start, TimeSpan.Zero)], Start.AddDays(29), Interval, Overlap).CreateNew.ShouldBeFalse();

    [Fact]
    public void An_old_key_triggers_a_new_one() =>
        KeyRotation.Plan([Key(Start, TimeSpan.Zero)], Start.AddDays(30), Interval, Overlap).CreateNew.ShouldBeTrue();

    [Fact]
    public void A_replaced_key_retires_only_after_the_overlap_since_its_successor_activated()
    {
        var old = Key(Start, TimeSpan.Zero);
        var successor = Key(Start.AddDays(30), TimeSpan.FromDays(1)); // activates on day 31

        KeyRotation.Plan([old, successor], Start.AddDays(37), Interval, Overlap).ToRetire.ShouldBeEmpty();
        KeyRotation.Plan([old, successor], Start.AddDays(38), Interval, Overlap).ToRetire.ShouldBe([old]);
    }

    [Fact]
    public void The_signer_is_the_newest_activated_key()
    {
        var old = Key(Start, TimeSpan.Zero);
        var pending = Key(Start.AddDays(30), TimeSpan.FromDays(1));

        KeyRotation.CurrentSigner([old, pending], Start.AddDays(30).AddHours(1)).ShouldBe(old);
        KeyRotation.CurrentSigner([old, pending], Start.AddDays(31)).ShouldBe(pending);
    }
}

public sealed class AuthenticationStrengthTests
{
    [Fact]
    public void Multi_factor_is_detected_and_can_be_added()
    {
        AuthenticationStrength.Password.IsMultiFactor.ShouldBeFalse();
        AuthenticationStrength.Password.WithMultiFactor().Methods.ShouldBe(["pwd", "mfa"]);
        new AuthenticationStrength(["mfa", "mfa", " "]).Methods.ShouldBe(["mfa"]);
    }

    [Fact]
    public void The_policy_decides_sign_in_and_step_up()
    {
        var strict = new MfaPolicy(RequireForSignIn: true, RequireForSensitiveActions: true);
        var lenient = new MfaPolicy(RequireForSignIn: false, RequireForSensitiveActions: false);

        strict.AllowsSignIn(AuthenticationStrength.Password).ShouldBeFalse();
        strict.SatisfiesStepUp(AuthenticationStrength.Password.WithMultiFactor()).ShouldBeTrue();
        lenient.SatisfiesStepUp(AuthenticationStrength.None).ShouldBeTrue();
    }

    [Fact]
    public void Session_lifetime_counts_from_sign_in()
    {
        var signedIn = new DateTimeOffset(2026, 10, 15, 8, 0, 0, TimeSpan.Zero);

        SessionLifetime.HasExpired(signedIn, signedIn.AddHours(7.9), TimeSpan.FromHours(8)).ShouldBeFalse();
        SessionLifetime.HasExpired(signedIn, signedIn.AddHours(8), TimeSpan.FromHours(8)).ShouldBeTrue();
    }
}

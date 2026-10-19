using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using JeffOps.Authentication.LocalAccounts.Domain;

namespace JeffOps.Authentication.LocalAccounts.Tests;

public sealed class PasswordHasherTests
{
    [Fact]
    public void A_hash_verifies_its_password_only()
    {
        var hash = PasswordHasher.Hash("correct horse", 10_000);

        hash.ShouldStartWith("v2.10000.");
        PasswordHasher.Verify(hash, "correct horse", 10_000).ShouldBe(new PasswordCheck(true, false));
        PasswordHasher.Verify(hash, "Correct horse", 10_000).Valid.ShouldBeFalse();
    }

    [Fact]
    public void Older_formats_and_weaker_iteration_counts_verify_and_ask_for_a_rehash()
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes("imported"), salt, 100_000, HashAlgorithmName.SHA256, 32);
        var v1 = string.Create(CultureInfo.InvariantCulture, $"v1.100000.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(key)}");

        PasswordHasher.Verify(v1, "imported", 10_000).ShouldBe(new PasswordCheck(true, true));
        PasswordHasher.Verify(PasswordHasher.Hash("pw", 10_000), "pw", 20_000).NeedsRehash.ShouldBeTrue();
    }

    [Theory]
    [InlineData("")]
    [InlineData("v3.1.AAAA.AAAA")]
    [InlineData("v2.x.AAAA.AAAA")]
    [InlineData("v2.1000.not base64.AAAA")]
    public void Malformed_hashes_never_match(string hash) =>
        PasswordHasher.Verify(hash, "anything").Valid.ShouldBeFalse();

    [Fact]
    public void Only_length_matters_for_passwords()
    {
        PasswordRules.Problem("short", 12).ShouldNotBeNull();
        PasswordRules.Problem("all lowercase words", 12).ShouldBeNull();
        PasswordRules.Problem(new string('x', 257), 12).ShouldNotBeNull();
    }
}

public sealed class TotpTests
{
    // RFC 6238 appendix B, SHA-1 secret "12345678901234567890": 94287082 at T=59 → last 6 digits.
    private static readonly byte[] RfcSecret = Encoding.ASCII.GetBytes("12345678901234567890");

    [Theory]
    [InlineData(59, "287082")]
    [InlineData(1111111109, "081804")]
    [InlineData(1234567890, "005924")]
    public void Codes_match_the_rfc_test_vectors(long unixSeconds, string expected) =>
        Totp.Code(RfcSecret, Totp.StepOf(DateTimeOffset.FromUnixTimeSeconds(unixSeconds))).ShouldBe(expected);

    [Fact]
    public void A_code_matches_within_one_step_of_drift_and_never_twice()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
        var previous = Totp.Code(RfcSecret, Totp.StepOf(now) - 1);

        var step = Totp.Match(RfcSecret, previous, now, lastUsedStep: null);

        step.ShouldBe(Totp.StepOf(now) - 1);
        Totp.Match(RfcSecret, previous, now, lastUsedStep: step).ShouldBeNull();
        Totp.Match(RfcSecret, Totp.Code(RfcSecret, Totp.StepOf(now) - 2), now, null).ShouldBeNull();
        Totp.Match(RfcSecret, "12345", now, null).ShouldBeNull();
    }

    [Fact]
    public void Secrets_are_shown_in_base32() => Totp.Base32(Encoding.ASCII.GetBytes("foobar")).ShouldBe("MZXW6YTBOI");
}

public sealed class LocalCredentialTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);
    private static readonly LockoutPolicy Lockout = new(3, TimeSpan.FromSeconds(2), TimeSpan.FromMinutes(15));

    private static LocalCredential WithPassword(string password)
    {
        var credential = LocalCredential.Create(Guid.NewGuid(), Now);
        credential.SetPassword(PasswordHasher.Hash(password, 10_000), Now);
        return credential;
    }

    [Fact]
    public void Lockout_starts_after_the_free_attempts_and_doubles()
    {
        Lockout.DelayAfter(3).ShouldBe(TimeSpan.Zero);
        Lockout.DelayAfter(4).ShouldBe(TimeSpan.FromSeconds(2));
        Lockout.DelayAfter(5).ShouldBe(TimeSpan.FromSeconds(4));
        Lockout.DelayAfter(40).ShouldBe(TimeSpan.FromMinutes(15));
    }

    [Fact]
    public void Failures_lock_and_a_success_after_the_lock_resets_the_count()
    {
        var credential = WithPassword("right password");
        for (var attempt = 0; attempt < 4; attempt++)
        {
            credential.CheckPassword("wrong", Now, Lockout, 10_000).ShouldBe(PasswordSignInResult.Failed);
        }

        credential.CheckPassword("right password", Now.AddSeconds(1), Lockout, 10_000).ShouldBe(PasswordSignInResult.LockedOut);
        credential.CheckPassword("right password", Now.AddSeconds(3), Lockout, 10_000).ShouldBe(PasswordSignInResult.Success);
        credential.FailedAttempts.ShouldBe(0);
    }

    [Fact]
    public void Recovery_codes_work_once_and_are_stored_hashed()
    {
        var credential = WithPassword("right password");
        credential.BeginTotp("protected");
        var codes = credential.ConfirmTotp(matchedStep: 1, recoveryCodeCount: 3);

        credential.RecoveryCodes.ShouldAllBe(code => !codes.Contains(code.Hash));
        credential.UseRecoveryCode(codes[0].ToLowerInvariant()).ShouldBeTrue();
        credential.UseRecoveryCode(codes[0]).ShouldBeFalse();
        credential.RecoveryCodes.Count.ShouldBe(2);
    }

    [Fact]
    public void Recovery_codes_carry_80_random_bits()
    {
        // LA-9: codes were ten hex digits (40 bits), so a leaked unsalted hash was quick to reverse.
        var credential = WithPassword("right password");
        credential.BeginTotp("protected");

        var codes = credential.ConfirmTotp(matchedStep: 1, recoveryCodeCount: 10);

        codes.ShouldAllBe(code => System.Text.RegularExpressions.Regex.IsMatch(code, "^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$"));
        codes.Distinct().Count().ShouldBe(10);
        credential.UseRecoveryCode(codes[3].Replace("-", string.Empty, StringComparison.Ordinal).ToLowerInvariant()).ShouldBeTrue();
    }

    [Fact]
    public void Recovery_codes_in_the_earlier_format_hash_as_before()
    {
        // Codes users already hold (ten hex digits) keep working until used or regenerated.
        RecoveryCode.HashOf("abcde-12345").ShouldBe(Convert.ToHexStringLower(SHA256.HashData("ABCDE12345"u8)));
    }

    [Fact]
    public void Removing_second_factors_clears_the_authenticator_codes_and_passkeys()
    {
        var credential = WithPassword("right password");
        credential.BeginTotp("protected");
        credential.ConfirmTotp(matchedStep: 1, recoveryCodeCount: 3);
        credential.SavePasskey([1, 2, 3], [4], "Laptop", Now, 0, null, true, false, false, [], [], Now);
        var stamp = credential.SecurityStamp;

        credential.RemoveSecondFactorsAndPasskeys();

        credential.TotpEnabled.ShouldBeFalse();
        credential.ProtectedTotpSecret.ShouldBeNull();
        credential.RecoveryCodes.ShouldBeEmpty();
        credential.Passkeys.ShouldBeEmpty();
        credential.SecurityStamp.ShouldNotBe(stamp);
        credential.PasswordHash.ShouldNotBeNull();
    }

    [Fact]
    public void A_password_change_rotates_the_security_stamp()
    {
        var credential = WithPassword("first password");
        var stamp = credential.SecurityStamp;

        credential.SetPassword(PasswordHasher.Hash("second password", 10_000), Now);

        credential.SecurityStamp.ShouldNotBe(stamp);
        credential.DomainEvents.OfType<LocalCredentialChanged>().ShouldContain(change => change.Change == "password");
    }
}

public sealed class AccountTokenTests
{
    [Fact]
    public void A_token_is_stored_hashed_and_used_once_before_it_expires()
    {
        var now = DateTimeOffset.UtcNow;
        var (token, secret) = AccountToken.Issue(Guid.NewGuid(), AccountTokenPurpose.PasswordReset, now, TimeSpan.FromMinutes(30));

        token.TokenHash.ShouldBe(AccountToken.HashOf(secret));
        token.TokenHash.ShouldNotContain(secret);
        token.Use(now.AddMinutes(31)).ShouldBeFalse();
        token.Use(now.AddMinutes(5)).ShouldBeTrue();
        token.Use(now.AddMinutes(6)).ShouldBeFalse();
    }
}

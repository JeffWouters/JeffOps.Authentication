using System.Security.Cryptography;
using System.Text;
using JeffOps.Authentication.SharedKernel.Domain;

namespace JeffOps.Authentication.LocalAccounts.Domain;

/// <summary>
/// Progressive lockout (I5): the first <see cref="FreeAttempts"/> failures cost nothing; each further failure locks the
/// credential for <see cref="BaseDelay"/> doubled per failure, up to <see cref="MaxDelay"/>. A success resets the count.
/// </summary>
public sealed record LockoutPolicy(int FreeAttempts, TimeSpan BaseDelay, TimeSpan MaxDelay)
{
    public static LockoutPolicy Default { get; } = new(3, TimeSpan.FromSeconds(2), TimeSpan.FromMinutes(15));

    public TimeSpan DelayAfter(int failures)
    {
        if (failures <= FreeAttempts)
        {
            return TimeSpan.Zero;
        }

        var exponent = Math.Min(failures - FreeAttempts - 1, 20);
        var delay = BaseDelay * Math.Pow(2, exponent);
        return delay < MaxDelay ? delay : MaxDelay;
    }
}

public enum PasswordSignInResult
{
    Success,
    Failed,
    LockedOut,
    NoPassword,
}

/// <summary>A registered passkey (WebAuthn credential), as ASP.NET Core Identity describes it.</summary>
public sealed class StoredPasskey
{
    internal StoredPasskey(Guid accountId, byte[] credentialId, byte[] publicKey, string? name, DateTimeOffset createdAt, uint signCount,
        string[]? transports, bool isUserVerified, bool isBackupEligible, bool isBackedUp, byte[] attestationObject, byte[] clientDataJson)
    {
        AccountId = accountId;
        CredentialId = credentialId;
        PublicKey = publicKey;
        Name = name;
        CreatedAt = createdAt;
        SignCount = signCount;
        Transports = transports;
        IsUserVerified = isUserVerified;
        IsBackupEligible = isBackupEligible;
        IsBackedUp = isBackedUp;
        AttestationObject = attestationObject;
        ClientDataJson = clientDataJson;
    }

    private StoredPasskey()
    {
        CredentialId = [];
        PublicKey = [];
        AttestationObject = [];
        ClientDataJson = [];
    }

    public Guid AccountId { get; private set; }

    public byte[] CredentialId { get; private set; }

    public byte[] PublicKey { get; private set; }

    public string? Name { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? LastUsedAt { get; private set; }

    public uint SignCount { get; private set; }

    public string[]? Transports { get; private set; }

    public bool IsUserVerified { get; private set; }

    public bool IsBackupEligible { get; private set; }

    public bool IsBackedUp { get; private set; }

    public byte[] AttestationObject { get; private set; }

    public byte[] ClientDataJson { get; private set; }

    internal void Used(uint signCount, bool isUserVerified, bool isBackedUp, DateTimeOffset now)
    {
        SignCount = signCount;
        IsUserVerified = isUserVerified;
        IsBackedUp = isBackedUp;
        LastUsedAt = now;
    }

    internal void Rename(string? name) => Name = string.IsNullOrWhiteSpace(name) ? null : name.Trim();
}

/// <summary>
/// A hashed single-use recovery code. Codes issued before they had 80 bits (ten hex digits, 40 bits) hash the same way and
/// keep working until used or regenerated.
/// </summary>
public sealed class RecoveryCode
{
    /// <summary>Random bytes per code: 80 bits.</summary>
    public const int Bytes = 10;

    internal RecoveryCode(Guid accountId, string hash)
    {
        AccountId = accountId;
        Hash = hash;
    }

    private RecoveryCode()
    {
        Hash = string.Empty;
    }

    public Guid AccountId { get; private set; }

    public string Hash { get; private set; }

    public static string HashOf(string code) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(code.Replace("-", string.Empty, StringComparison.Ordinal).Trim().ToUpperInvariant())));
}

/// <summary>
/// The local credentials of an account (id = the account id): a password, a TOTP authenticator with recovery codes, and
/// passkeys. Lockout counts failed password and second-factor attempts together.
/// </summary>
public sealed class LocalCredential : AggregateRoot<Guid>
{
    private readonly List<StoredPasskey> _passkeys = [];
    private readonly List<RecoveryCode> _recoveryCodes = [];

    private LocalCredential(Guid accountId, DateTimeOffset now)
        : base(accountId)
    {
        CreatedAt = now;
        SecurityStamp = NewStamp();
    }

    private LocalCredential()
    {
    }

    public string? PasswordHash { get; private set; }

    public DateTimeOffset? PasswordChangedAt { get; private set; }

    public int FailedAttempts { get; private set; }

    public DateTimeOffset? LockedUntil { get; private set; }

    /// <summary>The TOTP secret, protected by the infrastructure (never stored in clear).</summary>
    public string? ProtectedTotpSecret { get; private set; }

    /// <summary>Set once the user proved the authenticator works; until then the secret is only pending.</summary>
    public bool TotpEnabled { get; private set; }

    /// <summary>The last accepted TOTP step, so a code can't be replayed.</summary>
    public long? TotpLastStep { get; private set; }

    /// <summary>Changes whenever credentials change; sessions started earlier can be told apart.</summary>
    public string SecurityStamp { get; private set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; private set; }

    public IReadOnlyCollection<StoredPasskey> Passkeys => _passkeys.AsReadOnly();

    public IReadOnlyCollection<RecoveryCode> RecoveryCodes => _recoveryCodes.AsReadOnly();

    public bool HasSecondFactor => TotpEnabled;

    public static LocalCredential Create(Guid accountId, DateTimeOffset now) => new(accountId, now);

    public bool IsLockedOut(DateTimeOffset now) => LockedUntil is { } until && until > now;

    public void SetPassword(string passwordHash, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(passwordHash);
        PasswordHash = passwordHash;
        PasswordChangedAt = now;
        ResetLockout();
        SecurityStamp = NewStamp();
        Raise(new LocalCredentialChanged(Id, "password"));
    }

    /// <summary>Checks a password, applying lockout. A hash in an old format is replaced transparently on success.</summary>
    public PasswordSignInResult CheckPassword(string password, DateTimeOffset now, LockoutPolicy lockout, int iterations)
    {
        ArgumentNullException.ThrowIfNull(lockout);
        if (PasswordHash is null)
        {
            PasswordHasher.VerifyNothing(password, iterations);
            return PasswordSignInResult.NoPassword;
        }

        if (IsLockedOut(now))
        {
            // Still spend the work, so a locked account doesn't answer faster than a wrong password.
            PasswordHasher.VerifyNothing(password, iterations);
            return PasswordSignInResult.LockedOut;
        }

        var check = PasswordHasher.Verify(PasswordHash, password, iterations);
        if (!check.Valid)
        {
            Fail(now, lockout);
            return PasswordSignInResult.Failed;
        }

        if (check.NeedsRehash)
        {
            PasswordHash = PasswordHasher.Hash(password, iterations);
        }

        if (!HasSecondFactor)
        {
            ResetLockout();
        }

        return PasswordSignInResult.Success;
    }

    /// <summary>
    /// Reserves one sign-in attempt before a secret is checked: it counts as failed up front (locking progressively), so each
    /// of many parallel attempts counts, and an attempt is only checked once its reservation is saved. A successful check
    /// resets the count. False when locked out (nothing is checked then).
    /// </summary>
    public bool ReserveAttempt(DateTimeOffset now, LockoutPolicy lockout)
    {
        ArgumentNullException.ThrowIfNull(lockout);
        if (IsLockedOut(now))
        {
            return false;
        }

        Fail(now, lockout);
        return true;
    }

    /// <summary>
    /// Checks a password after <see cref="ReserveAttempt"/> (no lockout effects here). On success a hash in an old format is
    /// replaced. Accounts without a password always fail, after the same work.
    /// </summary>
    public bool VerifyPassword(string password, int iterations)
    {
        if (PasswordHash is null)
        {
            PasswordHasher.VerifyNothing(password, iterations);
            return false;
        }

        var check = PasswordHasher.Verify(PasswordHash, password, iterations);
        if (check.Valid && check.NeedsRehash)
        {
            PasswordHash = PasswordHasher.Hash(password, iterations);
        }

        return check.Valid;
    }

    /// <summary>Records a failed attempt (wrong password or second factor) and locks progressively.</summary>
    public void Fail(DateTimeOffset now, LockoutPolicy lockout)
    {
        ArgumentNullException.ThrowIfNull(lockout);
        FailedAttempts++;
        var delay = lockout.DelayAfter(FailedAttempts);
        if (delay > TimeSpan.Zero)
        {
            LockedUntil = now + delay;
        }
    }

    public void ResetLockout()
    {
        FailedAttempts = 0;
        LockedUntil = null;
    }

    // ---- TOTP ------------------------------------------------------------------------------------------------------------

    /// <summary>Stores a new, not yet confirmed authenticator secret (replacing any pending one; an enabled one stays until confirmed).</summary>
    public void BeginTotp(string protectedSecret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedSecret);
        if (TotpEnabled)
        {
            throw new InvalidOperationException("An authenticator is already enabled; disable it first.");
        }

        ProtectedTotpSecret = protectedSecret;
    }

    /// <summary>Enables the pending authenticator after a matching code, and issues recovery codes (returned once, in clear).</summary>
    public IReadOnlyList<string> ConfirmTotp(long matchedStep, int recoveryCodeCount)
    {
        if (ProtectedTotpSecret is null || TotpEnabled)
        {
            throw new InvalidOperationException("No authenticator is pending.");
        }

        TotpEnabled = true;
        TotpLastStep = matchedStep;
        SecurityStamp = NewStamp();
        Raise(new LocalCredentialChanged(Id, "totp_enabled"));
        return RegenerateRecoveryCodes(recoveryCodeCount);
    }

    /// <summary>Records an accepted TOTP code (completing a sign-in).</summary>
    public void AcceptTotp(long step)
    {
        TotpLastStep = step;
        ResetLockout();
    }

    /// <summary>Uses a recovery code; each works once.</summary>
    public bool UseRecoveryCode(string code)
    {
        var hash = RecoveryCode.HashOf(code ?? string.Empty);
        var match = _recoveryCodes.FirstOrDefault(candidate =>
            CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(candidate.Hash), Encoding.ASCII.GetBytes(hash)));
        if (match is null)
        {
            return false;
        }

        _recoveryCodes.Remove(match);
        ResetLockout();
        Raise(new LocalCredentialChanged(Id, "recovery_code_used"));
        return true;
    }

    /// <summary>
    /// Replaces the recovery codes with <paramref name="count"/> new ones, returned once in clear: 80 random bits each, as 16
    /// base32 characters in groups of four, so a leaked hash can't be reversed by trying every code.
    /// </summary>
    public IReadOnlyList<string> RegenerateRecoveryCodes(int count)
    {
        _recoveryCodes.Clear();
        var codes = new List<string>(count);
        for (var index = 0; index < count; index++)
        {
            var raw = Totp.Base32(RandomNumberGenerator.GetBytes(RecoveryCode.Bytes));
            var code = $"{raw[..4]}-{raw[4..8]}-{raw[8..12]}-{raw[12..]}";
            codes.Add(code);
            _recoveryCodes.Add(new RecoveryCode(Id, RecoveryCode.HashOf(code)));
        }

        return codes;
    }

    public void DisableTotp()
    {
        ProtectedTotpSecret = null;
        TotpEnabled = false;
        TotpLastStep = null;
        _recoveryCodes.Clear();
        SecurityStamp = NewStamp();
        Raise(new LocalCredentialChanged(Id, "totp_disabled"));
    }

    /// <summary>
    /// Removes the authenticator, its recovery codes and every passkey. For when a password reset is what proves the email
    /// address: whoever registered it before may have enrolled them.
    /// </summary>
    public void RemoveSecondFactorsAndPasskeys()
    {
        ProtectedTotpSecret = null;
        TotpEnabled = false;
        TotpLastStep = null;
        _recoveryCodes.Clear();
        _passkeys.Clear();
        SecurityStamp = NewStamp();
        Raise(new LocalCredentialChanged(Id, "second_factors_removed"));
    }

    // ---- Passkeys --------------------------------------------------------------------------------------------------------

    public StoredPasskey? FindPasskey(byte[] credentialId) =>
        _passkeys.FirstOrDefault(passkey => passkey.CredentialId.AsSpan().SequenceEqual(credentialId));

    /// <summary>Adds or updates a passkey (Identity calls this both on registration and after each use).</summary>
    public void SavePasskey(byte[] credentialId, byte[] publicKey, string? name, DateTimeOffset createdAt, uint signCount, string[]? transports,
        bool isUserVerified, bool isBackupEligible, bool isBackedUp, byte[] attestationObject, byte[] clientDataJson, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(credentialId);
        if (FindPasskey(credentialId) is { } existing)
        {
            existing.Used(signCount, isUserVerified, isBackedUp, now);
            existing.Rename(name ?? existing.Name);
            return;
        }

        _passkeys.Add(new StoredPasskey(Id, credentialId, publicKey, name, createdAt, signCount, transports, isUserVerified, isBackupEligible, isBackedUp, attestationObject, clientDataJson));
        SecurityStamp = NewStamp();
        Raise(new LocalCredentialChanged(Id, "passkey_added"));
    }

    public bool RemovePasskey(byte[] credentialId)
    {
        if (FindPasskey(credentialId) is not { } passkey)
        {
            return false;
        }

        _passkeys.Remove(passkey);
        SecurityStamp = NewStamp();
        Raise(new LocalCredentialChanged(Id, "passkey_removed"));
        return true;
    }

    private static string NewStamp() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
}

/// <summary>A local credential changed: a security notification and audit trigger.</summary>
public sealed record LocalCredentialChanged(Guid AccountId, string Change) : IDomainEvent;

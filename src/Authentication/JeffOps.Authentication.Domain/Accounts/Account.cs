using JeffOps.Authentication.SharedKernel.Domain;

namespace JeffOps.Authentication.Domain.Accounts;

public enum AccountStatus
{
    Active = 0,

    /// <summary>Temporarily locked, for example after repeated failed local sign-ins.</summary>
    Locked = 1,

    /// <summary>Disabled by an operator.</summary>
    Disabled = 2,
}

/// <summary>A user of the platform. Credentials live elsewhere: external logins here, local credentials in LocalAccounts.</summary>
public sealed class Account : AggregateRoot<Guid>
{
    /// <summary>The longest display name kept; longer ones (from a provider or SCIM) are cut.</summary>
    public const int MaxDisplayNameLength = 200;

    /// <summary>How precisely activity is recorded (<see cref="LastActiveAt"/>): at most one write a day per account.</summary>
    public static readonly TimeSpan ActivityPrecision = TimeSpan.FromDays(1);

    private readonly List<ExternalLogin> _externalLogins = [];

    private Account(Guid id, string email, string displayName, bool emailVerified, DateTimeOffset now)
        : base(id)
    {
        Email = NormalizeEmail(email);
        DisplayName = Clip(displayName);
        EmailVerified = emailVerified;
        Status = AccountStatus.Active;
        CreatedAt = now;
        UpdatedAt = now;
        LastActiveAt = now;
    }

    private Account()
    {
    }

    /// <summary>Lower-cased and trimmed. Not unique and never an identity key: external logins are linked by (issuer, subject).</summary>
    public string Email { get; private set; } = string.Empty;

    public bool EmailVerified { get; private set; }

    public string DisplayName { get; private set; } = string.Empty;

    public AccountStatus Status { get; private set; }

    /// <summary>
    /// Whether an operator disabled the account. Then only an operator enables it again: provisioning, which may enable an
    /// account it disabled itself, leaves it alone.
    /// </summary>
    public bool DisabledByOperator { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset UpdatedAt { get; private set; }

    /// <summary>
    /// Sessions signed in before this moment are over: set when credentials change or the user (or an operator) signs out
    /// everywhere. Null when sessions were never revoked.
    /// </summary>
    public DateTimeOffset? SessionsRevokedAt { get; private set; }

    /// <summary>
    /// When the account last signed in or used its tokens, to the day (<see cref="ActivityPrecision"/>). Inactive accounts are
    /// deleted from it, when the host turns that on.
    /// </summary>
    public DateTimeOffset LastActiveAt { get; private set; }

    /// <summary>When the user was told the account will be deleted for inactivity; any activity clears it.</summary>
    public DateTimeOffset? DeletionWarnedAt { get; private set; }

    public IReadOnlyCollection<ExternalLogin> ExternalLogins => _externalLogins.AsReadOnly();

    public bool CanAuthenticate => Status == AccountStatus.Active;

    public static Account Register(string email, string displayName, bool emailVerified, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        var account = new Account(Guid.CreateVersion7(now), email, displayName ?? string.Empty, emailVerified, now);
        account.Raise(new AccountRegistered(account.Id, account.Email));
        return account;
    }

    /// <summary>Creates an account for a first sign-in through an external provider.</summary>
    public static Account RegisterExternal(string email, string displayName, ExternalLoginKey login, string provider, DateTimeOffset now, bool emailVerified = true)
    {
        var account = Register(email, displayName, emailVerified, now);
        account.LinkExternalLogin(login, provider, now);
        return account;
    }

    /// <summary>Links an external login. Linking a key that is already linked is a no-op.</summary>
    public void LinkExternalLogin(ExternalLoginKey login, string provider, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(login);

        if (_externalLogins.Any(existing => existing.Key == login))
        {
            return;
        }

        _externalLogins.Add(new ExternalLogin(Id, login, provider, now));
        UpdatedAt = now;
    }

    /// <summary>Refreshes profile data an external provider reports on sign-in.</summary>
    public void UpdateProfile(string? email, string? displayName, DateTimeOffset now)
    {
        var changed = false;
        if (!string.IsNullOrWhiteSpace(email) && NormalizeEmail(email) != Email)
        {
            Email = NormalizeEmail(email);
            changed = true;
        }

        if (!string.IsNullOrWhiteSpace(displayName) && Clip(displayName) != DisplayName)
        {
            DisplayName = Clip(displayName);
            changed = true;
        }

        if (changed)
        {
            UpdatedAt = now;
        }
    }

    /// <summary>Records that the user proved they control the email address. Returns false when it already was verified.</summary>
    public bool MarkEmailVerified(DateTimeOffset now)
    {
        if (EmailVerified)
        {
            return false;
        }

        EmailVerified = true;
        UpdatedAt = now;
        return true;
    }

    /// <summary>
    /// Disables the account. Returns false when nothing changed: it already was disabled (for an operator: by an operator). An
    /// operator disabling an account provisioning disabled takes the disable over, so provisioning can't undo it.
    /// </summary>
    public bool Disable(DateTimeOffset now, bool byOperator = false)
    {
        if (Status == AccountStatus.Disabled)
        {
            if (!byOperator || DisabledByOperator)
            {
                return false;
            }

            DisabledByOperator = true;
            UpdatedAt = now;
            return true;
        }

        Status = AccountStatus.Disabled;
        DisabledByOperator = byOperator;
        UpdatedAt = now;
        Raise(new AccountStatusChanged(Id, Disabled: true));
        return true;
    }

    /// <summary>
    /// Re-enables a disabled or locked account. Returns false when nothing changed: it already was active, or an operator
    /// disabled it and <paramref name="byOperator"/> is false.
    /// </summary>
    public bool Enable(DateTimeOffset now, bool byOperator = true)
    {
        if (Status == AccountStatus.Active || (DisabledByOperator && !byOperator))
        {
            return false;
        }

        Status = AccountStatus.Active;
        DisabledByOperator = false;
        UpdatedAt = now;
        Raise(new AccountStatusChanged(Id, Disabled: false));
        return true;
    }

    /// <summary>
    /// Ends every session of the account: refresh tokens issued before <paramref name="now"/> stop working, and clients are
    /// told to drop their sessions. <paramref name="reason"/> is a stable code such as <c>password_changed</c>.
    /// </summary>
    public void RevokeSessions(DateTimeOffset now, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        SessionsRevokedAt = now;
        UpdatedAt = now;
        Raise(new AccountSessionsRevoked(Id, reason));
    }

    /// <summary>
    /// Records that the account signed in or used its tokens. Returns true when that changed something to save: at most once per
    /// <see cref="ActivityPrecision"/>, and at once while a deletion warning is pending, which it cancels.
    /// </summary>
    public bool RecordActivity(DateTimeOffset now)
    {
        if (DeletionWarnedAt is null && now - LastActiveAt < ActivityPrecision)
        {
            return false;
        }

        LastActiveAt = now;
        DeletionWarnedAt = null;
        return true;
    }

    /// <summary>Records that the user was told the account will be deleted for inactivity.</summary>
    public void WarnOfDeletion(DateTimeOffset now) => DeletionWarnedAt = now;

    /// <summary>
    /// Deletes the account; the repository removes it. <paramref name="reason"/> is a stable code such as <c>requested</c>, and
    /// clients and other services are told (<see cref="AccountDeleted"/>).
    /// </summary>
    public void Delete(DateTimeOffset now, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        UpdatedAt = now;
        Raise(new AccountDeleted(Id, reason));
    }

    /// <summary>Whether a session that signed in at <paramref name="signedInAt"/> has been revoked since (second precision, as <c>auth_time</c>).</summary>
    public bool IsSessionRevoked(DateTimeOffset signedInAt) =>
        SessionsRevokedAt is { } revoked && signedInAt.ToUnixTimeSeconds() < revoked.ToUnixTimeSeconds();

    private static string Clip(string displayName)
    {
        var trimmed = displayName.Trim();
        if (trimmed.Length <= MaxDisplayNameLength)
        {
            return trimmed;
        }

        // Never cut between the two halves of a surrogate pair.
        var length = char.IsHighSurrogate(trimmed[MaxDisplayNameLength - 1]) ? MaxDisplayNameLength - 1 : MaxDisplayNameLength;
        return trimmed[..length].TrimEnd();
    }

    public static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();
}

public sealed record AccountRegistered(Guid AccountId, string Email) : IDomainEvent;

public sealed record AccountStatusChanged(Guid AccountId, bool Disabled) : IDomainEvent;

/// <summary>Every session of the account was ended (<paramref name="Reason"/> is a stable code such as <c>password_changed</c>).</summary>
public sealed record AccountSessionsRevoked(Guid AccountId, string Reason) : IDomainEvent;

/// <summary>The account was deleted (<see cref="Account.Delete"/>); <paramref name="Reason"/> is a stable code.</summary>
public sealed record AccountDeleted(Guid AccountId, string Reason) : IDomainEvent;

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
    }

    private Account()
    {
    }

    /// <summary>Lower-cased and trimmed. Not unique and never an identity key: external logins are linked by (issuer, subject).</summary>
    public string Email { get; private set; } = string.Empty;

    public bool EmailVerified { get; private set; }

    public string DisplayName { get; private set; } = string.Empty;

    public AccountStatus Status { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset UpdatedAt { get; private set; }

    /// <summary>
    /// Sessions signed in before this moment are over: set when credentials change or the user (or an operator) signs out
    /// everywhere. Null when sessions were never revoked.
    /// </summary>
    public DateTimeOffset? SessionsRevokedAt { get; private set; }

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

    /// <summary>Disables the account. Returns false when it already was.</summary>
    public bool Disable(DateTimeOffset now)
    {
        if (Status == AccountStatus.Disabled)
        {
            return false;
        }

        Status = AccountStatus.Disabled;
        UpdatedAt = now;
        Raise(new AccountStatusChanged(Id, Disabled: true));
        return true;
    }

    /// <summary>Re-enables a disabled or locked account. Returns false when it already was active.</summary>
    public bool Enable(DateTimeOffset now)
    {
        if (Status == AccountStatus.Active)
        {
            return false;
        }

        Status = AccountStatus.Active;
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

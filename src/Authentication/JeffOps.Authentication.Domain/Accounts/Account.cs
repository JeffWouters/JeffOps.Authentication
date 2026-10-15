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
    private readonly List<ExternalLogin> _externalLogins = [];

    private Account(Guid id, string email, string displayName, bool emailVerified, DateTimeOffset now)
        : base(id)
    {
        Email = NormalizeEmail(email);
        DisplayName = displayName.Trim();
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

    public IReadOnlyCollection<ExternalLogin> ExternalLogins => _externalLogins.AsReadOnly();

    public bool CanAuthenticate => Status == AccountStatus.Active;

    public static Account Register(string email, string displayName, bool emailVerified, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        var account = new Account(Guid.CreateVersion7(now), email, displayName ?? string.Empty, emailVerified, now);
        account.Raise(new AccountRegistered(account.Id, account.Email));
        return account;
    }

    /// <summary>
    /// Creates an account for a first sign-in through an external provider. The provider vouched for the email address.
    /// </summary>
    public static Account RegisterExternal(string email, string displayName, ExternalLoginKey login, string provider, DateTimeOffset now)
    {
        var account = Register(email, displayName, emailVerified: true, now);
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

        if (!string.IsNullOrWhiteSpace(displayName) && displayName.Trim() != DisplayName)
        {
            DisplayName = displayName.Trim();
            changed = true;
        }

        if (changed)
        {
            UpdatedAt = now;
        }
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

    public static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();
}

public sealed record AccountRegistered(Guid AccountId, string Email) : IDomainEvent;

public sealed record AccountStatusChanged(Guid AccountId, bool Disabled) : IDomainEvent;

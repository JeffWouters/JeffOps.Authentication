using JeffOps.Authentication.LocalAccounts.Domain;

namespace JeffOps.Authentication.LocalAccounts.Application;

public interface ILocalCredentialRepository
{
    Task<LocalCredential?> FindAsync(Guid accountId, CancellationToken cancellationToken);

    Task<LocalCredential?> FindByPasskeyAsync(byte[] credentialId, CancellationToken cancellationToken);

    void Add(LocalCredential credential);
}

public interface IAccountTokenRepository
{
    Task<AccountToken?> FindAsync(string tokenHash, AccountTokenPurpose purpose, CancellationToken cancellationToken);

    Task<IReadOnlyList<AccountToken>> ListUnusedAsync(Guid accountId, AccountTokenPurpose purpose, CancellationToken cancellationToken);

    /// <summary>How many tokens of <paramref name="purpose"/> were issued to the account since <paramref name="since"/>.</summary>
    Task<int> CountIssuedSinceAsync(Guid accountId, AccountTokenPurpose purpose, DateTimeOffset since, CancellationToken cancellationToken);

    void Add(AccountToken token);
}

public interface ILocalUnitOfWork
{
    Task SaveChangesAsync(CancellationToken cancellationToken);

    /// <summary>Saves; false (nothing saved, nothing tracked any more) when another request changed the same rows first.</summary>
    Task<bool> TrySaveChangesAsync(CancellationToken cancellationToken);
}

/// <summary>Protects TOTP secrets at rest (Data Protection by default).</summary>
public interface ITotpSecretProtector
{
    string Protect(byte[] secret);

    byte[]? Unprotect(string protectedSecret);
}

/// <summary>
/// Sends the account emails. The default logs a warning instead; a host with local accounts must plug in real delivery.
/// Messages carry links, never passwords.
/// </summary>
public interface IAccountEmailSender
{
    Task SendVerificationAsync(string email, Uri link, CancellationToken cancellationToken);

    Task SendPasswordResetAsync(string email, Uri link, CancellationToken cancellationToken);

    /// <summary>Someone tried to register an email that already has an account: tell its owner instead of the requester.</summary>
    Task SendAlreadyRegisteredAsync(string email, CancellationToken cancellationToken);

    /// <summary>The six-digit code that completes a password sign-in (with <see cref="LocalAccountOptions.EmailCodes"/>).</summary>
    Task SendSignInCodeAsync(string email, string code, CancellationToken cancellationToken);
}

/// <summary>Stable error codes of local-account refusals.</summary>
public static class LocalAccountErrors
{
    public const string Disabled = "local_accounts_disabled";
    public const string RegistrationClosed = "registration_closed";
    public const string WeakPassword = "weak_password";
    public const string InvalidToken = "invalid_token";
    public const string InvalidCredentials = "invalid_credentials";
    public const string LockedOut = "locked_out";
    public const string EmailNotVerified = "email_not_verified";
    public const string AccountInactive = "account_inactive";
    public const string InvalidCode = "invalid_code";
    public const string NotFound = "not_found";
    public const string AlreadyEnabled = "already_enabled";
    public const string SsoRequired = "sso_required";
}

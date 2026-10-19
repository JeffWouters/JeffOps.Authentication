using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.LocalAccounts.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.LocalAccounts.Application.Features.SignIn;

/// <summary>
/// Signs in with email and password. Unknown emails, accounts without a password and wrong passwords all answer
/// <see cref="LocalSignInStatus.Failed"/> after the same hashing work. Account state (unverified, disabled) is only revealed
/// after the right password.
/// </summary>
public sealed record PasswordSignInCommand(string Email, string Password);

public sealed class PasswordSignInHandler(
    IAccountRepository accounts,
    IHomeRealmDirectory realms,
    IPendingLinks pendingLinks,
    ILocalCredentialRepository credentials,
    SignInCodes codes,
    ILocalUnitOfWork unitOfWork,
    IOptions<LocalAccountOptions> options,
    TimeProvider time) : ICommandHandler<PasswordSignInCommand, LocalSignInResult>
{
    public async Task<Result<LocalSignInResult>> HandleAsync(PasswordSignInCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var settings = options.Value;
        var now = time.GetUtcNow();

        var account = string.IsNullOrWhiteSpace(command.Email) ? null : await accounts.FindByEmailAsync(command.Email, cancellationToken).ConfigureAwait(false);

        // SSO-only refuses passwords, except to confirm a login the domain's own provider asked this account's owner to link.
        if (HomeRealm.DomainOf(command.Email) is { } domain
            && await realms.FindByDomainAsync(domain, cancellationToken).ConfigureAwait(false) is { SsoOnly: true } realm
            && !pendingLinks.Confirms(account?.Id, realm))
        {
            return new LocalSignInResult(LocalSignInStatus.SsoRequired);
        }
        var credential = account is null ? null : await credentials.FindAsync(account.Id, cancellationToken).ConfigureAwait(false);
        if (account is null || credential is null)
        {
            PasswordHasher.VerifyNothing(command.Password, settings.HashIterations);
            return LocalSignInResult.Failed;
        }

        // Reserve the attempt first (counted, saved), then check: parallel guesses each count, and a lockout stops the rest.
        credential = await AttemptReservation.ReserveAsync(credentials, unitOfWork, account.Id, now, settings.Lockout(), cancellationToken).ConfigureAwait(false);
        if (credential is null)
        {
            PasswordHasher.VerifyNothing(command.Password, settings.HashIterations);
            return new LocalSignInResult(LocalSignInStatus.LockedOut);
        }

        if (!credential.VerifyPassword(command.Password ?? string.Empty, settings.HashIterations))
        {
            return LocalSignInResult.Failed;
        }

        // The count resets only when the sign-in is complete: with a second factor (authenticator or emailed code) still to
        // come, the attempts stand until that succeeds.
        var secondFactor = credential.HasSecondFactor ? "authenticator" : settings.EmailCodes ? "email" : null;
        if (secondFactor is null)
        {
            credential.ResetLockout();
        }

        if (!await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
        {
            return LocalSignInResult.Failed;
        }

        var result = true switch
        {
            _ when !account.CanAuthenticate => new LocalSignInResult(LocalSignInStatus.AccountInactive),
            _ when settings.RequireVerifiedEmail && !account.EmailVerified => new LocalSignInResult(LocalSignInStatus.EmailNotVerified, account.Id),
            _ when secondFactor is not null => new LocalSignInResult(LocalSignInStatus.SecondFactorRequired, account.Id) { SecondFactor = secondFactor },
            _ => new LocalSignInResult(LocalSignInStatus.SignedIn, account.Id, ["pwd"]),
        };

        if (result.SecondFactor == "email")
        {
            await codes.SendAsync(account.Id, account.Email, force: true, cancellationToken).ConfigureAwait(false);
        }

        return result;
    }
}

/// <summary>
/// Emailed sign-in codes (the email second factor): one live code per account, valid for
/// <see cref="LocalAccountOptions.EmailCodeLifetime"/>, accepted once. A new code supersedes the old; asking again within a
/// minute keeps the current one, so the address can't be flooded.
/// </summary>
public sealed class SignInCodes(IAccountTokenRepository tokens, IAccountEmailSender email, ILocalUnitOfWork unitOfWork, IOptions<LocalAccountOptions> options, TimeProvider time)
{
    private static readonly TimeSpan ResendInterval = TimeSpan.FromMinutes(1);

    public async Task SendAsync(Guid accountId, string address, bool force, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var live = await tokens.ListUnusedAsync(accountId, AccountTokenPurpose.SignInCode, cancellationToken).ConfigureAwait(false);
        if (!force && live.Any(token => token.IsUsableAt(now) && now - token.CreatedAt < ResendInterval))
        {
            return;
        }

        // At most so many codes an hour, whatever asks: the current one stays valid meanwhile.
        if (await tokens.CountIssuedSinceAsync(accountId, AccountTokenPurpose.SignInCode, now.AddHours(-1), cancellationToken).ConfigureAwait(false) >= options.Value.MaxEmailCodesPerHour)
        {
            return;
        }

        foreach (var token in live)
        {
            token.Retire(now);
        }

        var (issued, code) = AccountToken.IssueCode(accountId, now, options.Value.EmailCodeLifetime);
        tokens.Add(issued);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await email.SendSignInCodeAsync(address, code, cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> UseAsync(Guid accountId, string code, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        var token = await tokens.FindAsync(AccountToken.CodeHash(accountId, code.Trim()), AccountTokenPurpose.SignInCode, cancellationToken).ConfigureAwait(false);
        return token is not null && token.AccountId == accountId && token.Use(time.GetUtcNow());
    }
}

/// <summary>Sends a new sign-in code to the account waiting for its second factor (at most once a minute).</summary>
public sealed record ResendSignInCodeCommand(Guid AccountId);

public sealed class ResendSignInCodeHandler(IAccountRepository accounts, SignInCodes codes, IOptions<LocalAccountOptions> options) : ICommandHandler<ResendSignInCodeCommand>
{
    public async Task<Result> HandleAsync(ResendSignInCodeCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (options.Value.EmailCodes && await accounts.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false) is { CanAuthenticate: true } account)
        {
            await codes.SendAsync(account.Id, account.Email, force: false, cancellationToken).ConfigureAwait(false);
        }

        return Result.Success();
    }
}

/// <summary>
/// Completes a password sign-in with an authenticator code or a recovery code — or, for accounts without an authenticator
/// when <see cref="LocalAccountOptions.EmailCodes"/> is on, the emailed code. Failed codes count towards lockout; a code is
/// accepted once.
/// </summary>
public sealed record SecondFactorCommand(Guid AccountId, string Code, bool IsRecoveryCode);

public sealed class SecondFactorHandler(
    IAccountRepository accounts,
    ILocalCredentialRepository credentials,
    SignInCodes codes,
    ILocalUnitOfWork unitOfWork,
    ITotpSecretProtector protector,
    IOptions<LocalAccountOptions> options,
    TimeProvider time) : ICommandHandler<SecondFactorCommand, LocalSignInResult>
{
    public async Task<Result<LocalSignInResult>> HandleAsync(SecondFactorCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var now = time.GetUtcNow();

        var credential = await credentials.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        var byEmail = credential is { TotpEnabled: false } && options.Value.EmailCodes && !command.IsRecoveryCode;
        if (credential is null || (!byEmail && credential is not { TotpEnabled: true, ProtectedTotpSecret: not null }))
        {
            return LocalSignInResult.Failed;
        }

        // Reserve the attempt first (counted, saved), then check the code: parallel guesses each count.
        credential = await AttemptReservation.ReserveAsync(credentials, unitOfWork, command.AccountId, now, options.Value.Lockout(), cancellationToken).ConfigureAwait(false);
        if (credential is null)
        {
            return new LocalSignInResult(LocalSignInStatus.LockedOut);
        }

        bool accepted;
        if (byEmail)
        {
            accepted = await codes.UseAsync(command.AccountId, command.Code, cancellationToken).ConfigureAwait(false);
        }
        else if (command.IsRecoveryCode)
        {
            accepted = credential.UseRecoveryCode(command.Code);
        }
        else
        {
            var secret = protector.Unprotect(credential.ProtectedTotpSecret!);
            var step = secret is null ? null : Totp.Match(secret, command.Code, now, credential.TotpLastStep);
            if (step is { } matched)
            {
                credential.AcceptTotp(matched);
            }

            accepted = step is not null;
        }

        if (!accepted)
        {
            return LocalSignInResult.Failed;
        }

        // Accepted: the attempts reset, and the code (emailed code, TOTP step, recovery code) is spent. Of two requests racing
        // with one code, only one saves.
        credential.ResetLockout();
        if (!await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
        {
            return LocalSignInResult.Failed;
        }

        return await accounts.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false) is { CanAuthenticate: true }
            ? new LocalSignInResult(LocalSignInStatus.SignedIn, command.AccountId, ["pwd", "otp", "mfa"])
            : new LocalSignInResult(LocalSignInStatus.AccountInactive);
    }
}

/// <summary>Reserves a sign-in attempt on an account's credential, retrying when parallel attempts collide.</summary>
internal static class AttemptReservation
{
    private const int MaxTries = 5;

    /// <summary>The credential with this attempt counted and saved, or null when the account is locked out (or too busy).</summary>
    public static async Task<LocalCredential?> ReserveAsync(
        ILocalCredentialRepository credentials,
        ILocalUnitOfWork unitOfWork,
        Guid accountId,
        DateTimeOffset now,
        LockoutPolicy lockout,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < MaxTries; attempt++)
        {
            if (await credentials.FindAsync(accountId, cancellationToken).ConfigureAwait(false) is not { } credential
                || !credential.ReserveAttempt(now, lockout))
            {
                return null;
            }

            if (await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
            {
                return credential;
            }
        }

        return null;
    }
}


using JeffOps.Authentication.Application.Abstractions;
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
    ILocalCredentialRepository credentials,
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
        var credential = account is null ? null : await credentials.FindAsync(account.Id, cancellationToken).ConfigureAwait(false);
        if (account is null || credential is null)
        {
            PasswordHasher.VerifyNothing(command.Password, settings.HashIterations);
            return LocalSignInResult.Failed;
        }

        var outcome = credential.CheckPassword(command.Password ?? string.Empty, now, settings.Lockout(), settings.HashIterations);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        return outcome switch
        {
            PasswordSignInResult.LockedOut => new LocalSignInResult(LocalSignInStatus.LockedOut),
            PasswordSignInResult.Success when !account.CanAuthenticate => new LocalSignInResult(LocalSignInStatus.AccountInactive),
            PasswordSignInResult.Success when settings.RequireVerifiedEmail && !account.EmailVerified => new LocalSignInResult(LocalSignInStatus.EmailNotVerified, account.Id),
            PasswordSignInResult.Success when credential.HasSecondFactor => new LocalSignInResult(LocalSignInStatus.SecondFactorRequired, account.Id),
            PasswordSignInResult.Success => new LocalSignInResult(LocalSignInStatus.SignedIn, account.Id, ["pwd"]),
            _ => LocalSignInResult.Failed,
        };
    }
}

/// <summary>
/// Completes a password sign-in with an authenticator code or a recovery code. Failed codes count towards lockout; a code is
/// accepted once.
/// </summary>
public sealed record SecondFactorCommand(Guid AccountId, string Code, bool IsRecoveryCode);

public sealed class SecondFactorHandler(
    IAccountRepository accounts,
    ILocalCredentialRepository credentials,
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
        if (credential is not { TotpEnabled: true, ProtectedTotpSecret: { } protectedSecret })
        {
            return LocalSignInResult.Failed;
        }

        if (credential.IsLockedOut(now))
        {
            return new LocalSignInResult(LocalSignInStatus.LockedOut);
        }

        bool accepted;
        if (command.IsRecoveryCode)
        {
            accepted = credential.UseRecoveryCode(command.Code);
        }
        else
        {
            var secret = protector.Unprotect(protectedSecret);
            var step = secret is null ? null : Totp.Match(secret, command.Code, now, credential.TotpLastStep);
            if (step is { } matched)
            {
                credential.AcceptTotp(matched);
            }

            accepted = step is not null;
        }

        if (!accepted)
        {
            credential.Fail(now, options.Value.Lockout());
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        if (!accepted)
        {
            return LocalSignInResult.Failed;
        }

        return await accounts.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false) is { CanAuthenticate: true }
            ? new LocalSignInResult(LocalSignInStatus.SignedIn, command.AccountId, ["pwd", "otp", "mfa"])
            : new LocalSignInResult(LocalSignInStatus.AccountInactive);
    }
}

using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.LocalAccounts.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.LocalAccounts.Application.Features.Authenticator;

public sealed record AuthenticatorSetup(string Secret, string OtpAuthUri);

/// <summary>Starts adding an authenticator app: a new secret, shown once as text and as an <c>otpauth://</c> URI.</summary>
public sealed record BeginAuthenticatorCommand(Guid AccountId);

public sealed class BeginAuthenticatorHandler(
    ILocalCredentialRepository credentials,
    IAccountRepository accounts,
    ILocalUnitOfWork unitOfWork,
    ITotpSecretProtector protector,
    IOptions<LocalAccountOptions> options) : ICommandHandler<BeginAuthenticatorCommand, AuthenticatorSetup>
{
    public async Task<Result<AuthenticatorSetup>> HandleAsync(BeginAuthenticatorCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        var credential = await credentials.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        var account = await accounts.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (credential is null || account is null)
        {
            return Error.NotFound(LocalAccountErrors.NotFound, "This account has no local sign-in.");
        }

        if (credential.TotpEnabled)
        {
            return Error.Conflict(LocalAccountErrors.AlreadyEnabled, "An authenticator is already set up. Remove it first.");
        }

        var secret = Totp.NewSecret();
        credential.BeginTotp(protector.Protect(secret));
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return new AuthenticatorSetup(Totp.Base32(secret), Totp.Uri(secret, options.Value.TotpIssuer, account.Email));
    }
}

/// <summary>Turns the pending authenticator on after a matching code; returns recovery codes, shown once.</summary>
public sealed record ConfirmAuthenticatorCommand(Guid AccountId, string Code);

public sealed class ConfirmAuthenticatorHandler(
    ILocalCredentialRepository credentials,
    ILocalUnitOfWork unitOfWork,
    ITotpSecretProtector protector,
    IOptions<LocalAccountOptions> options,
    TimeProvider time) : ICommandHandler<ConfirmAuthenticatorCommand, IReadOnlyList<string>>
{
    public async Task<Result<IReadOnlyList<string>>> HandleAsync(ConfirmAuthenticatorCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        var credential = await credentials.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (credential is not { TotpEnabled: false, ProtectedTotpSecret: { } pending })
        {
            return Error.NotFound(LocalAccountErrors.NotFound, "No authenticator is being set up.");
        }

        var secret = protector.Unprotect(pending);
        if (secret is null || Totp.Match(secret, command.Code, time.GetUtcNow(), null) is not { } step)
        {
            return Error.Failure(LocalAccountErrors.InvalidCode, "The code doesn't match. Check the time on your device and try again.");
        }

        var codes = credential.ConfirmTotp(step, options.Value.RecoveryCodeCount);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return Result.Success(codes);
    }
}

/// <summary>Removes the authenticator and recovery codes; needs the password.</summary>
public sealed record DisableAuthenticatorCommand(Guid AccountId, string Password);

public sealed class DisableAuthenticatorHandler(
    ILocalCredentialRepository credentials,
    ILocalUnitOfWork unitOfWork,
    CredentialChangeSessions sessions,
    IOptions<LocalAccountOptions> options,
    TimeProvider time) : ICommandHandler<DisableAuthenticatorCommand>
{
    public async Task<Result> HandleAsync(DisableAuthenticatorCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var settings = options.Value;

        var credential = await credentials.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (credential is null)
        {
            return Error.NotFound(LocalAccountErrors.NotFound, "This account has no local sign-in.");
        }

        var check = credential.CheckPassword(command.Password ?? string.Empty, time.GetUtcNow(), settings.Lockout(), settings.HashIterations);
        if (check == PasswordSignInResult.Success)
        {
            credential.DisableTotp();
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        if (check == PasswordSignInResult.Success)
        {
            await sessions.RevokeAsync(command.AccountId, "authenticator_removed", cancellationToken).ConfigureAwait(false);
        }

        return check == PasswordSignInResult.Success
            ? Result.Success()
            : Error.Forbidden(check == PasswordSignInResult.LockedOut ? LocalAccountErrors.LockedOut : LocalAccountErrors.InvalidCredentials, "The password is wrong.");
    }
}

/// <summary>Replaces the recovery codes (the old ones stop working); needs a current authenticator code.</summary>
public sealed record RegenerateRecoveryCodesCommand(Guid AccountId, string Code);

public sealed class RegenerateRecoveryCodesHandler(
    ILocalCredentialRepository credentials,
    ILocalUnitOfWork unitOfWork,
    ITotpSecretProtector protector,
    IOptions<LocalAccountOptions> options,
    TimeProvider time) : ICommandHandler<RegenerateRecoveryCodesCommand, IReadOnlyList<string>>
{
    public async Task<Result<IReadOnlyList<string>>> HandleAsync(RegenerateRecoveryCodesCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var now = time.GetUtcNow();

        var credential = await credentials.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (credential is not { TotpEnabled: true, ProtectedTotpSecret: { } protectedSecret })
        {
            return Error.NotFound(LocalAccountErrors.NotFound, "No authenticator is set up.");
        }

        var secret = protector.Unprotect(protectedSecret);
        if (secret is null || Totp.Match(secret, command.Code, now, credential.TotpLastStep) is not { } step)
        {
            credential.Fail(now, options.Value.Lockout());
            await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return Error.Failure(LocalAccountErrors.InvalidCode, "The code doesn't match.");
        }

        credential.AcceptTotp(step);
        var codes = credential.RegenerateRecoveryCodes(options.Value.RecoveryCodeCount);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return Result.Success(codes);
    }
}

using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.LocalAccounts.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.LocalAccounts.Application.Features.Passwords;

/// <summary>Changes the caller's password, re-authenticating with the current one (which counts towards lockout).</summary>
public sealed record ChangePasswordCommand(Guid AccountId, string CurrentPassword, string NewPassword);

public sealed class ChangePasswordHandler(
    ILocalCredentialRepository credentials,
    ILocalUnitOfWork unitOfWork,
    CredentialChangeSessions sessions,
    IOptions<LocalAccountOptions> options,
    TimeProvider time) : ICommandHandler<ChangePasswordCommand>
{
    public async Task<Result> HandleAsync(ChangePasswordCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var settings = options.Value;
        var now = time.GetUtcNow();

        if (PasswordRules.Problem(command.NewPassword, settings.MinimumPasswordLength) is { } problem)
        {
            return Error.Validation([new ValidationFailure(nameof(command.NewPassword), problem)]);
        }

        var credential = await credentials.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (credential is null)
        {
            return Error.NotFound(LocalAccountErrors.NotFound, "This account has no password.");
        }

        var check = credential.CheckPassword(command.CurrentPassword ?? string.Empty, now, settings.Lockout(), settings.HashIterations);
        if (check != PasswordSignInResult.Success)
        {
            await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return check == PasswordSignInResult.LockedOut
                ? Error.Forbidden(LocalAccountErrors.LockedOut, "Too many attempts. Try again later.")
                : Error.Forbidden(LocalAccountErrors.InvalidCredentials, "The current password is wrong.");
        }

        credential.SetPassword(PasswordHasher.Hash(command.NewPassword, settings.HashIterations), now);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await sessions.RevokeAsync(command.AccountId, "password_changed", cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

/// <summary>
/// Emails a reset link to a local account. Enumeration-safe: always succeeds, and the email is queued
/// (<see cref="IAccountMailQueue"/>), so the answer takes as long for an address without an account.
/// </summary>
public sealed record RequestPasswordResetCommand(string Email);

public sealed class RequestPasswordResetHandler(
    IAccountRepository accounts,
    ILocalCredentialRepository credentials,
    IAccountTokenRepository tokens,
    ILocalUnitOfWork unitOfWork,
    IAccountMailQueue mail,
    IOptions<LocalAccountOptions> options,
    TimeProvider time) : ICommandHandler<RequestPasswordResetCommand>
{
    public async Task<Result> HandleAsync(RequestPasswordResetCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var settings = options.Value;
        var now = time.GetUtcNow();

        if (await accounts.FindByEmailAsync(command.Email ?? string.Empty, cancellationToken).ConfigureAwait(false) is not { CanAuthenticate: true } account
            || await credentials.FindAsync(account.Id, cancellationToken).ConfigureAwait(false) is null)
        {
            return Result.Success();
        }

        foreach (var old in await tokens.ListUnusedAsync(account.Id, AccountTokenPurpose.PasswordReset, cancellationToken).ConfigureAwait(false))
        {
            old.Retire(now);
        }

        var (token, secret) = AccountToken.Issue(account.Id, AccountTokenPurpose.PasswordReset, now, settings.ResetTokenLifetime);
        tokens.Add(token);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        var (address, link) = (account.Email, new Uri(settings.Link(settings.ResetPasswordPath, secret)));
        mail.Enqueue((sender, cancellation) => sender.SendPasswordResetAsync(address, link, cancellation));
        return Result.Success();
    }
}

/// <summary>
/// Sets a new password with an emailed reset token. Also lifts a lockout, and proves control of the email address, so an
/// unverified account becomes verified. When it does, the authenticator, recovery codes and passkeys enrolled before go:
/// whoever registered the address without owning it may have added them.
/// </summary>
public sealed record ResetPasswordCommand(string Token, string NewPassword);

public sealed class ResetPasswordHandler(
    IAccountTokenRepository tokens,
    ILocalCredentialRepository credentials,
    ILocalUnitOfWork unitOfWork,
    IAccountRepository accounts,
    IUnitOfWork accountUnitOfWork,
    IOptions<LocalAccountOptions> options,
    TimeProvider time) : ICommandHandler<ResetPasswordCommand>
{
    public async Task<Result> HandleAsync(ResetPasswordCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var settings = options.Value;
        var now = time.GetUtcNow();

        if (PasswordRules.Problem(command.NewPassword, settings.MinimumPasswordLength) is { } problem)
        {
            return Error.Validation([new ValidationFailure(nameof(command.NewPassword), problem)]);
        }

        var token = await tokens.FindAsync(AccountToken.HashOf(command.Token), AccountTokenPurpose.PasswordReset, cancellationToken).ConfigureAwait(false);
        var credential = token is null ? null : await credentials.FindAsync(token.AccountId, cancellationToken).ConfigureAwait(false);
        if (token is null || credential is null || !token.Use(now))
        {
            return Error.Failure(LocalAccountErrors.InvalidToken, "The link is invalid or has expired. Ask for a new one.");
        }

        var account = await accounts.FindAsync(token.AccountId, cancellationToken).ConfigureAwait(false);
        if (account is { EmailVerified: false })
        {
            credential.RemoveSecondFactorsAndPasskeys();
        }

        credential.SetPassword(PasswordHasher.Hash(command.NewPassword, settings.HashIterations), now);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        // A reset proves control of the email address, and whoever knew the old password is signed out.
        if (account is not null)
        {
            account.MarkEmailVerified(now);
            account.RevokeSessions(now, "password_reset");
            await accountUnitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        return Result.Success();
    }
}

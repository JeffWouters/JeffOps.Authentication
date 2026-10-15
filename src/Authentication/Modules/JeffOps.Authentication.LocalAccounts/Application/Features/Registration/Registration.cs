using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.LocalAccounts.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.LocalAccounts.Application.Features.Registration;

/// <summary>
/// Creates a local account and emails a verification link. Enumeration-safe: an email that already has an account gets the
/// same answer and the same work, and its owner is told by email instead.
/// </summary>
public sealed record RegisterLocalAccountCommand(string Email, string Password, string? DisplayName);

public sealed class RegisterLocalAccountHandler(
    IAccountRepository accounts,
    IHomeRealmDirectory realms,
    IUnitOfWork accountUnitOfWork,
    ILocalCredentialRepository credentials,
    IAccountTokenRepository tokens,
    ILocalUnitOfWork unitOfWork,
    IAccountEmailSender email,
    IOptions<LocalAccountOptions> options,
    TimeProvider time) : ICommandHandler<RegisterLocalAccountCommand>
{
    public async Task<Result> HandleAsync(RegisterLocalAccountCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var settings = options.Value;

        if (!settings.AllowRegistration)
        {
            return Error.Forbidden(LocalAccountErrors.RegistrationClosed, "Registration is closed.");
        }

        if (string.IsNullOrWhiteSpace(command.Email) || !command.Email.Contains('@', StringComparison.Ordinal))
        {
            return Error.Validation([new ValidationFailure(nameof(command.Email), "Enter an email address.")]);
        }

        if (PasswordRules.Problem(command.Password, settings.MinimumPasswordLength) is { } problem)
        {
            return Error.Validation([new ValidationFailure(nameof(command.Password), problem)]);
        }

        if (HomeRealm.DomainOf(command.Email) is { } domain
            && await realms.FindByDomainAsync(domain, cancellationToken).ConfigureAwait(false) is { SsoOnly: true })
        {
            return Error.Forbidden(LocalAccountErrors.SsoRequired, "Your organization requires signing in with its identity provider.");
        }

        var now = time.GetUtcNow();
        var hash = PasswordHasher.Hash(command.Password, settings.HashIterations);

        if (await accounts.FindByEmailAsync(command.Email, cancellationToken).ConfigureAwait(false) is not null)
        {
            await email.SendAlreadyRegisteredAsync(Account.NormalizeEmail(command.Email), cancellationToken).ConfigureAwait(false);
            return Result.Success();
        }

        var account = Account.Register(command.Email, command.DisplayName ?? string.Empty, emailVerified: false, now);
        accounts.Add(account);
        await accountUnitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        var credential = LocalCredential.Create(account.Id, now);
        credential.SetPassword(hash, now);
        credentials.Add(credential);
        var (token, secret) = AccountToken.Issue(account.Id, AccountTokenPurpose.EmailVerification, now, settings.VerificationTokenLifetime);
        tokens.Add(token);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        await email.SendVerificationAsync(account.Email, new Uri(settings.Link(settings.VerifyEmailPath, secret)), cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

/// <summary>Completes email verification with the emailed token.</summary>
public sealed record VerifyEmailCommand(string Token);

public sealed class VerifyEmailHandler(
    IAccountTokenRepository tokens,
    ILocalUnitOfWork unitOfWork,
    IAccountRepository accounts,
    IUnitOfWork accountUnitOfWork,
    TimeProvider time) : ICommandHandler<VerifyEmailCommand>
{
    public async Task<Result> HandleAsync(VerifyEmailCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var now = time.GetUtcNow();

        var token = await tokens.FindAsync(AccountToken.HashOf(command.Token), AccountTokenPurpose.EmailVerification, cancellationToken).ConfigureAwait(false);
        if (token is null || !token.Use(now))
        {
            return Error.Failure(LocalAccountErrors.InvalidToken, "The link is invalid or has expired. Ask for a new one.");
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        if (await accounts.FindAsync(token.AccountId, cancellationToken).ConfigureAwait(false) is { } account && account.MarkEmailVerified(now))
        {
            await accountUnitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        return Result.Success();
    }
}

/// <summary>Sends a fresh verification link to an unverified local account. Enumeration-safe: always succeeds.</summary>
public sealed record ResendVerificationCommand(string Email);

public sealed class ResendVerificationHandler(
    IAccountRepository accounts,
    ILocalCredentialRepository credentials,
    IAccountTokenRepository tokens,
    ILocalUnitOfWork unitOfWork,
    IAccountEmailSender email,
    IOptions<LocalAccountOptions> options,
    TimeProvider time) : ICommandHandler<ResendVerificationCommand>
{
    public async Task<Result> HandleAsync(ResendVerificationCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var settings = options.Value;
        var now = time.GetUtcNow();

        if (await accounts.FindByEmailAsync(command.Email ?? string.Empty, cancellationToken).ConfigureAwait(false) is not { EmailVerified: false } account
            || await credentials.FindAsync(account.Id, cancellationToken).ConfigureAwait(false) is null)
        {
            return Result.Success();
        }

        foreach (var old in await tokens.ListUnusedAsync(account.Id, AccountTokenPurpose.EmailVerification, cancellationToken).ConfigureAwait(false))
        {
            old.Retire(now);
        }

        var (token, secret) = AccountToken.Issue(account.Id, AccountTokenPurpose.EmailVerification, now, settings.VerificationTokenLifetime);
        tokens.Add(token);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await email.SendVerificationAsync(account.Email, new Uri(settings.Link(settings.VerifyEmailPath, secret)), cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

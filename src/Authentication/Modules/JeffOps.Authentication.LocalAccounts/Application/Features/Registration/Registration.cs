using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.LocalAccounts.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.LocalAccounts.Application.Features.Registration;

/// <summary>
/// Creates a local account and emails a verification link. Enumeration-safe: an email that already has an account gets the
/// same answer and the same work, and its owner is told by email instead (emails are queued, so sending takes no request time).
/// The email-domain policy of external sign-ins applies (<see cref="FederationOptions.AllowedEmailDomains"/>,
/// <see cref="FederationOptions.OpenRegistration"/>): outside Development, registration is closed unless it is open or the
/// address is in an allowed domain. An allowed domain admits only when sign-in requires the verified address.
/// </summary>
public sealed record RegisterLocalAccountCommand(string Email, string Password, string? DisplayName);

public sealed class RegisterLocalAccountHandler(
    IAccountRepository accounts,
    IHomeRealmDirectory realms,
    IUnitOfWork accountUnitOfWork,
    ILocalCredentialRepository credentials,
    IAccountTokenRepository tokens,
    ILocalUnitOfWork unitOfWork,
    IAccountMailQueue mail,
    IOptions<LocalAccountOptions> options,
    IOptions<FederationOptions> federation,
    IHostEnvironment environment,
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

        if (!federation.Value.AllowsEmailDomain(command.Email, emailVerified: settings.RequireVerifiedEmail, environment.IsDevelopment()))
        {
            return federation.Value.AllowedEmailDomains.Count == 0
                ? Error.Forbidden(LocalAccountErrors.RegistrationClosed, "Registration is closed.")
                : Error.Forbidden(LocalAccountErrors.DomainNotAllowed, "Accounts with this email domain can't be created here.");
        }

        var now = time.GetUtcNow();
        var hash = PasswordHasher.Hash(command.Password, settings.HashIterations);

        if (await accounts.FindByEmailAsync(command.Email, cancellationToken).ConfigureAwait(false) is not null)
        {
            var owner = Account.NormalizeEmail(command.Email);
            mail.Enqueue((sender, cancellation) => sender.SendAlreadyRegisteredAsync(owner, cancellation));
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

        var (address, link) = (account.Email, new Uri(settings.Link(settings.VerifyEmailPath, secret)));
        mail.Enqueue((sender, cancellation) => sender.SendVerificationAsync(address, link, cancellation));
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

/// <summary>Sends a fresh verification link to an unverified local account. Enumeration-safe: always succeeds, and the email is queued.</summary>
public sealed record ResendVerificationCommand(string Email);

public sealed class ResendVerificationHandler(
    IAccountRepository accounts,
    ILocalCredentialRepository credentials,
    IAccountTokenRepository tokens,
    ILocalUnitOfWork unitOfWork,
    IAccountMailQueue mail,
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
        var (address, link) = (account.Email, new Uri(settings.Link(settings.VerifyEmailPath, secret)));
        mail.Enqueue((sender, cancellation) => sender.SendVerificationAsync(address, link, cancellation));
        return Result.Success();
    }
}

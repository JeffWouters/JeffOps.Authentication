using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Application.Features.Accounts;

public static class AccountErrors
{
    public const string NotFound = "account_not_found";
    public const string CannotDisableSelf = "account_cannot_disable_self";
}

/// <summary>An account's contact details, for services that notify users.</summary>
public sealed record AccountContact(Guid Id, string Email, string DisplayName, bool EmailVerified);

// ---- SetAccountStatus --------------------------------------------------------------------------------------------------

/// <summary>An operator disables or re-enables an account (the kill switch). The endpoint has authorized the operator.</summary>
public sealed record SetAccountStatusCommand(Guid ActorId, Guid AccountId, bool Disable);

public sealed class SetAccountStatusHandler(
    IAccountRepository accounts,
    IUnitOfWork unitOfWork,
    IAuditSink audit,
    TimeProvider time) : ICommandHandler<SetAccountStatusCommand>
{
    public async Task<Result> HandleAsync(SetAccountStatusCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (command.Disable && command.ActorId == command.AccountId)
        {
            return Error.Failure(AccountErrors.CannotDisableSelf, "You cannot disable your own account.");
        }

        var account = await accounts.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (account is null)
        {
            return Error.NotFound(AccountErrors.NotFound, "No such account.");
        }

        var now = time.GetUtcNow();
        if (command.Disable ? account.Disable(now) : account.Enable(now))
        {
            await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            await audit.WriteAsync(
                new AuditRecord(command.Disable ? "account.disabled" : "account.enabled", "account", account.Id.ToString())
                {
                    ActorId = command.ActorId,
                    OccurredAt = now,
                    Severity = AuditSeverity.Warning,
                },
                cancellationToken).ConfigureAwait(false);
        }

        return Result.Success();
    }
}

// ---- GetAccountContact / FindAccountByEmail ----------------------------------------------------------------------------

/// <summary>
/// Signs an account out everywhere: the user themselves (<paramref name="ActorId"/> equals <paramref name="AccountId"/>), or an
/// operator for someone else (for example after a reported compromise).
/// </summary>
public sealed record RevokeSessionsCommand(Guid ActorId, Guid AccountId);

public sealed class RevokeSessionsHandler(IAccountRepository accounts, IUnitOfWork unitOfWork, IAuditSink audit, TimeProvider time)
    : ICommandHandler<RevokeSessionsCommand>
{
    public async Task<Result> HandleAsync(RevokeSessionsCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var account = await accounts.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (account is null)
        {
            return Error.NotFound(AccountErrors.NotFound, "No such account.");
        }

        var now = time.GetUtcNow();
        var self = command.ActorId == command.AccountId;
        account.RevokeSessions(now, self ? "signed_out_everywhere" : "revoked_by_operator");
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("account.sessions_revoked", "account", account.Id.ToString())
        {
            ActorId = command.ActorId,
            OccurredAt = now,
            Severity = self ? AuditSeverity.Information : AuditSeverity.Warning,
        }, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

public sealed record GetAccountContactQuery(Guid AccountId);

public sealed class GetAccountContactHandler(IAccountRepository accounts) : IQueryHandler<GetAccountContactQuery, AccountContact>
{
    public async Task<Result<AccountContact>> HandleAsync(GetAccountContactQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var account = await accounts.FindAsync(query.AccountId, cancellationToken).ConfigureAwait(false);
        return account is null ? Error.NotFound(AccountErrors.NotFound, "No such account.") : Contact(account);
    }

    internal static AccountContact Contact(Account account) =>
        new(account.Id, account.Email, account.DisplayName, account.EmailVerified);
}

public sealed record FindAccountByEmailQuery(string Email);

public sealed class FindAccountByEmailHandler(IAccountRepository accounts) : IQueryHandler<FindAccountByEmailQuery, AccountContact>
{
    public async Task<Result<AccountContact>> HandleAsync(FindAccountByEmailQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        if (string.IsNullOrWhiteSpace(query.Email))
        {
            return Error.NotFound(AccountErrors.NotFound, "No such account.");
        }

        var account = await accounts.FindByEmailAsync(Account.NormalizeEmail(query.Email), cancellationToken).ConfigureAwait(false);
        return account is null ? Error.NotFound(AccountErrors.NotFound, "No such account.") : GetAccountContactHandler.Contact(account);
    }
}

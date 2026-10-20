using System.Globalization;
using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Abstractions.Notifications;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Application.Features.Accounts;

public static class AccountErrors
{
    public const string NotFound = "account_not_found";
    public const string CannotDisableSelf = "account_cannot_disable_self";
}

/// <summary>Why an account was deleted, as audited and announced (<c>auth.account.deleted.v1</c>).</summary>
public static class AccountDeletionReasons
{
    public const string Requested = "requested";
    public const string Operator = "operator";
    public const string Inactive = "inactive";
}

/// <summary>An account's contact details, for services that notify users.</summary>
public sealed record AccountContact(Guid Id, string Email, string DisplayName, bool EmailVerified);

// ---- SetAccountStatus --------------------------------------------------------------------------------------------------

/// <summary>
/// An operator disables or re-enables an account (the kill switch). The endpoint has authorized the operator. Only an operator
/// enables an account an operator disabled.
/// </summary>
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

        // An operator's disable is recorded as theirs (and audited) even when provisioning had disabled the account already,
        // so provisioning can't enable it again.
        var now = time.GetUtcNow();
        if (command.Disable ? account.Disable(now, byOperator: true) : account.Enable(now, byOperator: true))
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

// ---- DeleteAccount -----------------------------------------------------------------------------------------------------

/// <summary>
/// Deletes an account: by its user (<paramref name="ActorId"/> equals <paramref name="AccountId"/>), an operator, or for
/// inactivity (no actor). The endpoint has authorized the caller.
/// </summary>
public sealed record DeleteAccountCommand(Guid? ActorId, Guid AccountId, string Reason);

/// <summary>
/// Every module's data about the account goes first (<see cref="IAccountDataEraser"/>, once none of them objects), then the
/// account and its logins. Clients get a back-channel logout and other services <c>auth.account.deleted.v1</c>. Audit records
/// stay: they name the account by its id only.
/// </summary>
public sealed class DeleteAccountHandler(
    IAccountRepository accounts,
    IEnumerable<IAccountDataEraser> erasers,
    IUnitOfWork unitOfWork,
    IAuditSink audit,
    TimeProvider time) : ICommandHandler<DeleteAccountCommand>
{
    public async Task<Result> HandleAsync(DeleteAccountCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var account = await accounts.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (account is null)
        {
            return Error.NotFound(AccountErrors.NotFound, "No such account.");
        }

        var all = erasers.ToList();
        foreach (var eraser in all)
        {
            if (await eraser.BlockerAsync(account.Id, cancellationToken).ConfigureAwait(false) is { } blocker)
            {
                return Error.Conflict(blocker.Code, blocker.Message);
            }
        }

        foreach (var eraser in all)
        {
            await eraser.EraseAsync(account.Id, cancellationToken).ConfigureAwait(false);
        }

        var now = time.GetUtcNow();
        account.Delete(now, command.Reason);
        accounts.Remove(account);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("account.deleted", "account", account.Id.ToString())
        {
            ActorId = command.ActorId,
            OccurredAt = now,
            Severity = AuditSeverity.Warning,
            Details = new Dictionary<string, string?> { ["reason"] = command.Reason },
        }, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

// ---- DeleteInactiveAccounts --------------------------------------------------------------------------------------------

/// <summary>One pass over inactive accounts (<see cref="TokenServerOptions.InactiveAccounts"/>): delete those due, warn the next.</summary>
public sealed record DeleteInactiveAccountsCommand;

/// <param name="Warned">Users told their account will be deleted.</param>
/// <param name="Deleted">Accounts deleted.</param>
/// <param name="Kept">
/// Accounts due that can't be deleted (<see cref="IAccountDataEraser.BlockerAsync"/>): tried again a notice period later, without
/// telling the user, so they never hold up the others.
/// </param>
public sealed record InactiveAccountsResult(int Warned, int Deleted, int Kept);

public sealed class DeleteInactiveAccountsHandler(
    IAccountRepository accounts,
    IUnitOfWork unitOfWork,
    ICommandHandler<DeleteAccountCommand> delete,
    IEnumerable<IAccountDataEraser> erasers,
    IEnumerable<INotifier> notifiers,
    IOptions<TokenServerOptions> options,
    TimeProvider time) : ICommandHandler<DeleteInactiveAccountsCommand, InactiveAccountsResult>
{
    /// <summary>The most accounts deleted, and the most warned, in one pass.</summary>
    public const int BatchSize = 100;

    public async Task<Result<InactiveAccountsResult>> HandleAsync(DeleteInactiveAccountsCommand command, CancellationToken cancellationToken)
    {
        var settings = options.Value.InactiveAccounts;
        if (settings.DeleteAfter is not { } deleteAfter)
        {
            return new InactiveAccountsResult(0, 0, 0);
        }

        // Warned once inactive for DeleteAfter - WarnBefore; deleted WarnBefore after that, when still inactive.
        var now = time.GetUtcNow();
        var inactiveSince = now - (deleteAfter - settings.WarnBefore);
        var deleted = 0;
        var kept = 0;
        foreach (var account in await accounts.ListDueForDeletionAsync(inactiveSince, now - settings.WarnBefore, BatchSize, cancellationToken).ConfigureAwait(false))
        {
            var result = await delete.HandleAsync(new DeleteAccountCommand(null, account.Id, AccountDeletionReasons.Inactive), cancellationToken).ConfigureAwait(false);
            if (result.IsSuccess)
            {
                deleted++;
            }
            else if (result.Error.Type == ErrorType.Conflict)
            {
                // Can't be deleted now: back of the queue, so a crowd of these never holds up the others.
                account.WarnOfDeletion(now);
                kept++;
            }
        }

        // Those that can't be deleted are queued all the same, but their users aren't told of a deletion that won't happen.
        var toWarn = await accounts.ListToWarnOfDeletionAsync(inactiveSince, BatchSize, cancellationToken).ConfigureAwait(false);
        var toTell = new List<Account>();
        foreach (var account in toWarn)
        {
            account.WarnOfDeletion(now);
            if (!await IsBlockedAsync(account.Id, cancellationToken).ConfigureAwait(false))
            {
                toTell.Add(account);
            }
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        var deletesOn = (now + settings.WarnBefore).ToString("d MMMM yyyy", CultureInfo.InvariantCulture);
        foreach (var account in toTell)
        {
            foreach (var notifier in notifiers)
            {
                await notifier.NotifyAsync(
                    new UserNotification(account.Id, "account.deletion_scheduled", "Your account will be deleted",
                        $"Your account hasn't been used for a long time, so it will be deleted on {deletesOn}. Sign in before then to keep it.")
                    {
                        Priority = NotificationPriority.High,
                    },
                    cancellationToken).ConfigureAwait(false);
            }
        }

        return new InactiveAccountsResult(toTell.Count, deleted, kept);
    }

    private async Task<bool> IsBlockedAsync(Guid accountId, CancellationToken cancellationToken)
    {
        foreach (var eraser in erasers)
        {
            if (await eraser.BlockerAsync(accountId, cancellationToken).ConfigureAwait(false) is not null)
            {
                return true;
            }
        }

        return false;
    }
}

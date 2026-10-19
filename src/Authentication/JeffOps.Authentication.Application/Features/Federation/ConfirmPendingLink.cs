using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Abstractions.Notifications;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Application.Features.Federation.ConfirmPendingLink;

/// <summary>
/// The user behind <paramref name="AccountId"/> signed in through <paramref name="SignedInProvider"/> (null when the sign-in
/// doesn't record one); if this browser holds a pending link for that account from another provider, attach it now.
/// </summary>
public sealed record ConfirmPendingLinkCommand(Guid AccountId, string? SignedInProvider);

/// <summary>
/// Completes a pending link (<see cref="IPendingLinks"/>): the account's owner proved an existing sign-in method, so the
/// external login a tenant's provider asserted for them is attached, audited and announced to the user. A pending link for
/// another account is dropped. Answers whether a login was linked.
/// </summary>
public sealed class ConfirmPendingLinkHandler(
    IAccountRepository accounts,
    IUnitOfWork unitOfWork,
    IPendingLinks pendingLinks,
    IAuditSink audit,
    IEnumerable<INotifier> notifiers,
    TimeProvider time) : ICommandHandler<ConfirmPendingLinkCommand, bool>
{
    public async Task<Result<bool>> HandleAsync(ConfirmPendingLinkCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (pendingLinks.Current is not { } pending)
        {
            return false;
        }

        // Signing in through the provider that asked for the link proves nothing new; keep waiting for another method.
        if (pending.AccountId == command.AccountId && string.Equals(command.SignedInProvider, pending.Provider, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        pendingLinks.Clear();
        var now = time.GetUtcNow();
        var login = new ExternalLoginKey(pending.Issuer, pending.Subject);
        if (pending.AccountId != command.AccountId || pending.ExpiresAt <= now
            || await accounts.FindByExternalLoginAsync(login, cancellationToken).ConfigureAwait(false) is not null
            || await accounts.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false) is not { CanAuthenticate: true } account
            || account.ExternalLogins.Any(existing => string.Equals(existing.Issuer, login.Issuer, StringComparison.Ordinal)))
        {
            return false;
        }

        account.LinkExternalLogin(login, pending.Provider, now);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(
            new AuditRecord("signin.external_login_confirmed", "account", account.Id.ToString())
            {
                OccurredAt = now,
                ActorId = account.Id,
                Details = new Dictionary<string, string?> { ["provider"] = pending.Provider, ["issuer"] = login.Issuer, ["confirmed_with"] = command.SignedInProvider },
            },
            cancellationToken).ConfigureAwait(false);

        foreach (var notifier in notifiers)
        {
            await notifier.NotifyAsync(
                new UserNotification(account.Id, "signin.external_login_linked", "A sign-in method was added",
                    $"You can now sign in to your account through {pending.Provider}. If this wasn't you, remove it and contact your administrator."),
                cancellationToken).ConfigureAwait(false);
        }

        return true;
    }
}

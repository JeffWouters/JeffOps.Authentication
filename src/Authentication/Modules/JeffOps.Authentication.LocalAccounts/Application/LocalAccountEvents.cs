using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Abstractions.Notifications;
using JeffOps.Authentication.LocalAccounts.Domain;
using JeffOps.Authentication.SharedKernel.Domain;

namespace JeffOps.Authentication.LocalAccounts.Application;

/// <summary>Audits every credential change and tells the user, so a change they didn't make doesn't go unnoticed.</summary>
public sealed class LocalAccountEvents(IAuditSink audit, INotifier notifier, TimeProvider time) : IDomainEventHandler<LocalCredentialChanged>
{
    public async Task HandleAsync(LocalCredentialChanged domainEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);

        await audit.WriteAsync(new AuditRecord($"local_credential.{domainEvent.Change}", "account", domainEvent.AccountId.ToString())
        {
            ActorId = domainEvent.AccountId,
            OccurredAt = time.GetUtcNow(),
            Severity = AuditSeverity.Information,
        }, cancellationToken).ConfigureAwait(false);

        var message = domainEvent.Change switch
        {
            "password" => "Your password was changed.",
            "totp_enabled" => "An authenticator app was added to your account.",
            "totp_disabled" => "The authenticator app was removed from your account.",
            "passkey_added" => "A passkey was added to your account.",
            "passkey_removed" => "A passkey was removed from your account.",
            "recovery_code_used" => "A recovery code was used to sign in to your account.",
            _ => null,
        };
        if (message is not null)
        {
            await notifier.NotifyAsync(new UserNotification(domainEvent.AccountId, $"security.{domainEvent.Change}", "Security change on your account",
                message + " If this wasn't you, reset your password and contact support.") { Priority = NotificationPriority.High }, cancellationToken).ConfigureAwait(false);
        }
    }
}

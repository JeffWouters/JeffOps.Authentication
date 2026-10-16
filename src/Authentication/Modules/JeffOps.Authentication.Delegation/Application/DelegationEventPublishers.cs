using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.Abstractions.Notifications;
using JeffOps.Authentication.Delegation.Domain;
using JeffOps.Authentication.SharedKernel.Domain;

namespace JeffOps.Authentication.Delegation.Application;

/// <summary>
/// Turns grant changes into integration events, audit records and notifications: the target hears about every request on
/// their account (and about break-glass immediately), and every step is audited.
/// </summary>
public sealed class DelegationEventPublishers(IEventPublisher publisher, IAuditSink audit, INotifier notifier, TimeProvider time) :
    IDomainEventHandler<DelegationGrantRequested>,
    IDomainEventHandler<DelegationGrantApproved>,
    IDomainEventHandler<DelegationGrantStarted>,
    IDomainEventHandler<DelegationGrantFinished>
{
    public async Task HandleAsync(DelegationGrantRequested domainEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);
        var grant = domainEvent.Grant;
        if (grant is not ImpersonationGrant impersonation)
        {
            await PublishAsync(grant, "requested", cancellationToken).ConfigureAwait(false);
            return;
        }

        // The target hears first (break-glass is urgent), and a failing step doesn't stop the others.
        await AllAsync(() => NotifyTargetAsync(impersonation, cancellationToken), () => PublishAsync(grant, "requested", cancellationToken)).ConfigureAwait(false);
    }

    private Task NotifyTargetAsync(ImpersonationGrant impersonation, CancellationToken cancellationToken)
    {
        var grant = impersonation;
        {
            var notification = impersonation.BreakGlass
                ? new UserNotification(
                    impersonation.TargetUserId,
                    "impersonation.break_glass",
                    "A platform administrator is acting as you",
                    $"A platform administrator started acting as you (break-glass). Reason: {impersonation.Reason}. You can end it at any time.")
                { Priority = NotificationPriority.Urgent, ReferenceId = grant.Id.ToString() }
                : new UserNotification(
                    impersonation.TargetUserId,
                    "impersonation.requested",
                    "Someone asks to act as you",
                    $"A support user asks to act as you. Approve before {impersonation.ApprovalDeadline:HH:mm} UTC if you expect this; otherwise ignore or deny it.")
                { Priority = NotificationPriority.High, ReferenceId = grant.Id.ToString() };
            return notifier.NotifyAsync(notification, cancellationToken);
        }
    }

    /// <summary>Runs every step, then reports all failures together.</summary>
    private static async Task AllAsync(params Func<Task>[] steps)
    {
        List<Exception>? failures = null;
        foreach (var step in steps)
        {
            try
            {
                await step().ConfigureAwait(false);
            }
#pragma warning disable CA1031 // Collected and rethrown below, after the remaining steps ran.
            catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
            {
                (failures ??= []).Add(exception);
            }
        }

        if (failures is not null)
        {
            throw new AggregateException("Delivering a delegation change partly failed.", failures);
        }
    }

    public Task HandleAsync(DelegationGrantApproved domainEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);
        return PublishAsync(domainEvent.Grant, "approved", cancellationToken);
    }

    public Task HandleAsync(DelegationGrantStarted domainEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);
        return PublishAsync(domainEvent.Grant, "started", cancellationToken);
    }

    public Task HandleAsync(DelegationGrantFinished domainEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);
        var stage = domainEvent.Status switch
        {
            DelegationGrantStatus.Denied => "denied",
            DelegationGrantStatus.Expired => "expired",
            DelegationGrantStatus.Revoked => "revoked",
            _ => "ended",
        };
        return PublishAsync(domainEvent.Grant, stage, cancellationToken);
    }

    private async Task PublishAsync(DelegationGrant grant, string stage, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        IntegrationEvent integrationEvent;
        AuditRecord record;

        if (grant is ImpersonationGrant impersonation)
        {
            integrationEvent = new ImpersonationEvent(stage, grant.Id, grant.ActorUserId, impersonation.TargetUserId, impersonation.TargetTenantId, impersonation.BreakGlass) { OccurredAt = now };
            record = new AuditRecord($"impersonation.{stage}", "impersonation_grant", grant.Id.ToString())
            {
                ActorId = grant.ActorUserId,
                TenantId = impersonation.TargetTenantId,
                OccurredAt = now,
                Severity = impersonation.BreakGlass || stage is "started" or "revoked" ? AuditSeverity.Warning : AuditSeverity.Information,
                Details = new Dictionary<string, string?>
                {
                    ["target"] = impersonation.TargetUserId.ToString(),
                    ["breakGlass"] = impersonation.BreakGlass ? "true" : "false",
                    ["reason"] = impersonation.Reason,
                    ["endedReason"] = grant.EndedReason,
                },
            };
        }
        else
        {
            var access = (TenantAccessGrant)grant;
            integrationEvent = new TenantAccessEvent(stage, grant.Id, grant.ActorUserId, grant.ActorOrganizationId, access.TargetTenantId) { OccurredAt = now };
            record = new AuditRecord($"tenant_access.{stage}", "tenant_access_grant", grant.Id.ToString())
            {
                ActorId = grant.ActorUserId,
                TenantId = access.TargetTenantId,
                OccurredAt = now,
                Severity = stage is "started" or "revoked" ? AuditSeverity.Warning : AuditSeverity.Information,
                Details = new Dictionary<string, string?> { ["organization"] = grant.ActorOrganizationId?.ToString(), ["endedReason"] = grant.EndedReason },
            };
        }

        // The audit record first: it is the one that must not be lost.
        await AllAsync(() => audit.WriteAsync(record, cancellationToken), () => publisher.PublishAsync(integrationEvent, cancellationToken)).ConfigureAwait(false);
    }
}

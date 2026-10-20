using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Application.Abstractions;

namespace JeffOps.Authentication.Application.Federation;

/// <summary>
/// Sessions whose provider is re-checked (<see cref="ExternalProviderInfo.SessionCheckInterval"/>): the provider's refresh
/// token is kept with the session and redeemed at most once per interval when the session's tokens are issued or refreshed,
/// so what the provider decides since (a disabled user, revoked sessions, a Conditional Access condition no longer met)
/// reaches the session here within the interval rather than at the end of its lifetime.
/// </summary>
public interface IProviderSessionChecks
{
    /// <summary>Keeps <paramref name="provider"/>'s refresh token for the session <paramref name="sessionId"/> until <paramref name="expiresAt"/>.</summary>
    Task KeepAsync(string provider, string sessionId, Guid accountId, string refreshToken, DateTimeOffset expiresAt, CancellationToken cancellationToken);

    /// <summary>
    /// Whether the provider still accepts the session, asking it when the last check is older than the provider's interval.
    /// True for sessions that aren't checked, and while the provider can't be reached: an outage isn't a verdict.
    /// </summary>
    Task<bool> StandsAsync(string sessionId, CancellationToken cancellationToken);
}

/// <summary>Ends a session its provider no longer accepts, as signing out would: its tokens stop working and clients are told.</summary>
public sealed class ProviderSessionGuard(
    IProviderSessionChecks checks,
    IEndedSessions endedSessions,
    ISessionLogoutNotifier notifier,
    IAuditSink audit,
    TimeProvider time)
{
    /// <summary>False when the provider of <paramref name="sessionId"/> refused it; the session has then been ended.</summary>
    public async Task<bool> StandsAsync(Guid accountId, string? sessionId, CancellationToken cancellationToken)
    {
        if (sessionId is null || await checks.StandsAsync(sessionId, cancellationToken).ConfigureAwait(false))
        {
            return true;
        }

        var now = time.GetUtcNow();
        await endedSessions.EndAsync(sessionId, accountId, now, cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("session.ended_by_provider", "account", accountId.ToString())
        {
            OccurredAt = now,
            Details = new Dictionary<string, string?> { ["session"] = sessionId },
        }, cancellationToken).ConfigureAwait(false);
        await notifier.SessionEndedAsync(accountId, sessionId, cancellationToken).ConfigureAwait(false);
        return false;
    }
}

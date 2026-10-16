using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Application.Features.Sessions.EndSession;

/// <summary>The user signed out at the token server: the session's refresh tokens stop working and clients are told.</summary>
public sealed record EndSessionCommand(Guid AccountId, string SessionId);

/// <summary>
/// Ends one sign-in session (its other sessions, on other devices, continue): its tokens can no longer be refreshed, and
/// every client with a back-channel logout URI receives a <c>logout_token</c> naming the session (<c>sid</c>).
/// </summary>
public sealed class EndSessionHandler(IEndedSessions endedSessions, ISessionLogoutNotifier notifier, IAuditSink audit, TimeProvider time)
    : ICommandHandler<EndSessionCommand>
{
    public async Task<Result> HandleAsync(EndSessionCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var now = time.GetUtcNow();

        await endedSessions.EndAsync(command.SessionId, command.AccountId, now, cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("session.ended", "account", command.AccountId.ToString())
        {
            ActorId = command.AccountId,
            OccurredAt = now,
            Details = new Dictionary<string, string?> { ["session"] = command.SessionId },
        }, cancellationToken).ConfigureAwait(false);
        await notifier.SessionEndedAsync(command.AccountId, command.SessionId, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

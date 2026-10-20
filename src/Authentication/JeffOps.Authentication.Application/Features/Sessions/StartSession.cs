using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Application.Features.Sessions.StartSession;

/// <summary>
/// Starts an interactive session for an account that has just signed in (at the authorize endpoint).
/// </summary>
/// <param name="AccountId">The signed-in account.</param>
/// <param name="Strength">How strongly the sign-in authenticated.</param>
/// <param name="SignedInAt">When the sign-in happened; the session's absolute lifetime counts from here.</param>
/// <param name="Scopes">The scopes granted to the client.</param>
/// <param name="TenantHint">Start in this tenant when the account has a membership there.</param>
/// <param name="SessionId">The sign-in session (<c>sid</c>) the tokens belong to.</param>
/// <param name="Upstream">What the client receives of the provider's answer (<see cref="JeffOps.Authentication.Application.Federation.UpstreamIdentity"/>).</param>
/// <param name="ClientId">The client the session is for: its own session lifetime applies.</param>
public sealed record StartSessionCommand(
    Guid AccountId,
    AuthenticationStrength Strength,
    DateTimeOffset SignedInAt,
    IReadOnlyCollection<string> Scopes,
    Guid? TenantHint = null,
    string? SessionId = null,
    IReadOnlyList<System.Security.Claims.Claim>? Upstream = null,
    string? ClientId = null);

public sealed class StartSessionHandler(
    IAccountRepository accounts,
    IUnitOfWork unitOfWork,
    IEndedSessions endedSessions,
    SessionBuilder sessions,
    JeffOps.Authentication.Application.Federation.ProviderSessionGuard providerSessions,
    IEventPublisher events,
    JeffOps.Authentication.Abstractions.Auditing.IAuditSink audit,
    JeffOps.Authentication.Abstractions.Claims.ClaimNames names,
    Microsoft.Extensions.Options.IOptions<TokenServerOptions> options,
    TimeProvider time) : ICommandHandler<StartSessionCommand, IssuedIdentity>
{
    public async Task<Result<IssuedIdentity>> HandleAsync(StartSessionCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        var account = await accounts.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (account is not { CanAuthenticate: true })
        {
            return Error.Unauthorized(GrantErrors.AccountInactive, "This account is not active.");
        }

        // The sign-in itself must still stand: not past its lifetime, not revoked for the account (a password change, a
        // provider's logout of every session), not ended by signing out (here, or at the provider through single logout).
        var lifetime = options.Value.SessionLifetimeOf(command.ClientId);
        if (SessionLifetime.HasExpired(command.SignedInAt, time.GetUtcNow(), lifetime))
        {
            return Error.Unauthorized(GrantErrors.SessionExpired, "The session has reached its maximum lifetime. Sign in again.");
        }

        if (account.IsSessionRevoked(command.SignedInAt)
            || (command.SessionId is { } ended && await endedSessions.IsEndedAsync(ended, cancellationToken).ConfigureAwait(false)))
        {
            return Error.Unauthorized(GrantErrors.SessionRevoked, "This session was ended. Sign in again.");
        }

        // The provider the user signed in through may have ended the session since: asked again at most once per its interval.
        if (!await providerSessions.StandsAsync(account.Id, command.SessionId, cancellationToken).ConfigureAwait(false))
        {
            return Error.Unauthorized(GrantErrors.SessionRevoked, "Your identity provider ended this session. Sign in again.");
        }

        if (!sessions.AllowsSignIn(command.Strength))
        {
            return Error.Forbidden(GrantErrors.MfaRequired, "This platform requires a multi-factor sign-in.");
        }

        var standing = await sessions.StandingAsync(account.Id, null, cancellationToken).ConfigureAwait(false);
        if (command.TenantHint is { } hint)
        {
            var hinted = await sessions.StandingAsync(account.Id, hint, cancellationToken).ConfigureAwait(false);
            if (hinted.IsSuccess)
            {
                standing = hinted;
            }
        }

        if (standing.IsFailure)
        {
            return standing.Error;
        }

        var claims = sessions.UserClaims(account, command.Strength, command.SignedInAt, standing.Value);
        if (command.SessionId is { } sessionId)
        {
            claims.Add(new System.Security.Claims.Claim(names.SessionId, sessionId));
        }

        // A first-party client receives the identity the user signed in with at the provider: recorded, as it says who they are there.
        if (command.Upstream is { Count: > 0 } upstream)
        {
            claims.AddRange(upstream);
            await audit.WriteAsync(new JeffOps.Authentication.Abstractions.Auditing.AuditRecord("session.upstream_identity_forwarded", "account", account.Id.ToString())
            {
                ActorId = account.Id,
                OccurredAt = time.GetUtcNow(),
                Details = new Dictionary<string, string?>
                {
                    ["provider"] = upstream.FirstOrDefault(claim => claim.Type == JeffOps.Authentication.Application.Federation.UpstreamIdentity.ProviderClaim)?.Value,
                    ["issuer"] = upstream.FirstOrDefault(claim => claim.Type == JeffOps.Authentication.Application.Federation.UpstreamIdentity.IssuerClaim)?.Value,
                    ["subject"] = upstream.FirstOrDefault(claim => claim.Type == JeffOps.Authentication.Application.Federation.UpstreamIdentity.SubjectClaim)?.Value,
                    ["claims"] = string.Join(' ', upstream.Select(claim => claim.Type).Distinct(StringComparer.Ordinal)),
                },
            }, cancellationToken).ConfigureAwait(false);
        }

        if (account.RecordActivity(time.GetUtcNow()))
        {
            await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        await events.PublishAsync(
            new AccountSignedInEvent(account.Id, standing.Value.Membership?.TenantId) { OccurredAt = time.GetUtcNow() },
            cancellationToken).ConfigureAwait(false);

        return new IssuedIdentity(account.Id.ToString(), claims, command.Scopes)
        {
            SessionEndsAt = command.SignedInAt + lifetime,
        };
    }
}

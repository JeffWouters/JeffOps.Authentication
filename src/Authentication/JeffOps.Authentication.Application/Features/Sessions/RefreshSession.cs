using System.Globalization;
using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Application.Features.Sessions.RefreshSession;

/// <summary>
/// Re-issues a session from a stored grant (a refresh token or an authorization code), rebuilding every claim from live
/// state. The stored principal contributes only who signed in, when, how strongly, and in which tenant.
/// </summary>
/// <param name="Stored">The principal stored with the refresh token or code.</param>
/// <param name="Scopes">The scopes of the grant.</param>
/// <param name="ClientId">The client redeeming the grant: what it may receive of the provider's answer is checked again.</param>
public sealed record RefreshSessionCommand(ClaimsPrincipal Stored, IReadOnlyCollection<string> Scopes, string? ClientId = null);

public sealed class RefreshSessionHandler(
    IAccountRepository accounts,
    SessionBuilder sessions,
    IEndedSessions endedSessions,
    JeffOps.Authentication.Application.Federation.ProviderSessionGuard providerSessions,
    ClaimNames names,
    IOptions<TokenServerOptions> options,
    TimeProvider time) : ICommandHandler<RefreshSessionCommand, IssuedIdentity>
{
    public async Task<Result<IssuedIdentity>> HandleAsync(RefreshSessionCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var stored = command.Stored;

        if (!long.TryParse(stored.FindFirst(names.AuthenticationTime)?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var signedInSeconds))
        {
            return Error.Unauthorized(GrantErrors.SessionExpired, "This session has no recorded sign-in time. Sign in again.");
        }

        var signedInAt = DateTimeOffset.FromUnixTimeSeconds(signedInSeconds);
        var lifetime = options.Value.SessionLifetimeOf(command.ClientId);
        if (SessionLifetime.HasExpired(signedInAt, time.GetUtcNow(), lifetime))
        {
            return Error.Unauthorized(GrantErrors.SessionExpired, "The session has reached its maximum lifetime. Sign in again.");
        }

        if (!Guid.TryParse(stored.FindFirst(names.Subject)?.Value, out var accountId))
        {
            return Error.Unauthorized(GrantErrors.InvalidGrant, "The grant does not identify an account.");
        }

        var account = await accounts.FindAsync(accountId, cancellationToken).ConfigureAwait(false);
        if (account is not { CanAuthenticate: true })
        {
            return Error.Unauthorized(GrantErrors.AccountInactive, "The account no longer exists or is not active.");
        }

        if (account.IsSessionRevoked(signedInAt))
        {
            return Error.Unauthorized(GrantErrors.SessionRevoked, "This session was ended, for example after a password change. Sign in again.");
        }

        // Signing out at the token server ends that one session.
        var sessionId = SignInPrincipal.SessionId(stored, names);
        if (sessionId is not null && await endedSessions.IsEndedAsync(sessionId, cancellationToken).ConfigureAwait(false))
        {
            return Error.Unauthorized(GrantErrors.SessionRevoked, "You signed out of this session. Sign in again.");
        }

        // The provider the user signed in through may have ended the session since: asked again at most once per its interval.
        if (!await providerSessions.StandsAsync(account.Id, sessionId, cancellationToken).ConfigureAwait(false))
        {
            return Error.Unauthorized(GrantErrors.SessionRevoked, "Your identity provider ended this session. Sign in again.");
        }

        var strength = new AuthenticationStrength(stored.FindAll(names.AuthenticationMethods).Select(claim => claim.Value));
        if (!sessions.AllowsSignIn(strength))
        {
            return Error.Forbidden(GrantErrors.MfaRequired, "This platform requires a multi-factor sign-in. Sign in again.");
        }

        Guid? boundTenant = Guid.TryParse(stored.FindFirst(names.Tenant)?.Value, out var tenant) ? tenant : null;
        var standing = await sessions.StandingAsync(account.Id, boundTenant, cancellationToken).ConfigureAwait(false);
        if (standing.IsFailure)
        {
            return standing.Error;
        }

        var claims = sessions.UserClaims(account, strength, signedInAt, standing.Value);
        if (sessionId is not null)
        {
            claims.Add(new Claim(names.SessionId, sessionId));
        }

        claims.AddRange(JeffOps.Authentication.Application.Federation.UpstreamIdentity.FromGrant(stored, JeffOps.Authentication.Application.Federation.ClientProviders.Find(options.Value, command.ClientId), names));

        return new IssuedIdentity(account.Id.ToString(), claims, command.Scopes)
        {
            SessionEndsAt = signedInAt + lifetime,
        };
    }
}

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
public sealed record RefreshSessionCommand(ClaimsPrincipal Stored, IReadOnlyCollection<string> Scopes);

public sealed class RefreshSessionHandler(
    IAccountRepository accounts,
    SessionBuilder sessions,
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
        if (SessionLifetime.HasExpired(signedInAt, time.GetUtcNow(), options.Value.SessionLifetime))
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

        return new IssuedIdentity(account.Id.ToString(), sessions.UserClaims(account, strength, signedInAt, standing.Value), command.Scopes)
        {
            SessionEndsAt = signedInAt + options.Value.SessionLifetime,
        };
    }
}

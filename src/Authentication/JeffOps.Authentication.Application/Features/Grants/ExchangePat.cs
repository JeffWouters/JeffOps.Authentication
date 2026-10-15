using System.Globalization;
using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Domain.PersonalAccessTokens;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Application.Features.Grants.ExchangePat;

/// <summary>Exchanges a personal access token for a short-lived access token.</summary>
public sealed record ExchangePatCommand(string Secret, IReadOnlyCollection<string> Scopes);

/// <summary>
/// Validates the PAT (hash, effective expiry including the current maximum lifetime, revocation), the owner's live standing
/// in the PAT's tenant, and issues a short-lived token carrying the PAT's permission ceiling. No refresh token.
/// </summary>
public sealed class ExchangePatHandler(
    IPersonalAccessTokenRepository tokens,
    IAccountRepository accounts,
    IUnitOfWork unitOfWork,
    SessionBuilder sessions,
    ClaimNames names,
    IOptions<TokenServerOptions> options,
    TimeProvider time) : ICommandHandler<ExchangePatCommand, IssuedIdentity>
{
    public const string PatIdClaim = "pat_id";
    public const string PatCredential = "pat";

    public async Task<Result<IssuedIdentity>> HandleAsync(ExchangePatCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var settings = options.Value.Pat;
        var now = time.GetUtcNow();

        if (string.IsNullOrWhiteSpace(command.Secret))
        {
            return Error.Unauthorized(GrantErrors.TokenInvalid, "A personal access token is required.");
        }

        var pat = await tokens.FindBySecretHashAsync(PatSecret.Hash(command.Secret.Trim()), cancellationToken).ConfigureAwait(false);
        if (pat is null || !pat.IsActive(now, settings.MaxLifetime))
        {
            return Error.Unauthorized(GrantErrors.TokenInvalid, "The personal access token is invalid, expired, or revoked.");
        }

        var account = await accounts.FindAsync(pat.AccountId, cancellationToken).ConfigureAwait(false);
        if (account is not { CanAuthenticate: true })
        {
            return Error.Unauthorized(GrantErrors.AccountInactive, "The token's account no longer exists or is not active.");
        }

        var standing = await sessions.StandingAsync(account.Id, pat.TenantId, cancellationToken).ConfigureAwait(false);
        if (standing.IsFailure)
        {
            return standing.Error;
        }

        var claims = new List<Claim>
        {
            new(names.Subject, account.Id.ToString()),
            new(names.Email, account.Email),
            new(names.CredentialType, PatCredential),
            new(PatIdClaim, pat.Id.ToString()),
            new(names.AuthenticationTime, now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
        };
        claims.AddRange(pat.Ceiling().Select(permission => new Claim(names.PatCeiling, permission)));

        var steppedUp = !options.Value.Mfa.RequireForSensitiveActions
            || settings.PatsSatisfyStepUp
            || (pat.AllowSensitiveActions && settings.AllowSensitiveActionPats);
        if (steppedUp)
        {
            claims.Add(new Claim(names.StepUp, names.StepUpSatisfied));
        }

        sessions.AddTenantClaims(claims, standing.Value);

        pat.MarkUsed(now);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        return new IssuedIdentity(account.Id.ToString(), claims, command.Scopes)
        {
            AccessTokenLifetime = settings.TokenLifetime,
            AllowRefresh = false,
        };
    }
}

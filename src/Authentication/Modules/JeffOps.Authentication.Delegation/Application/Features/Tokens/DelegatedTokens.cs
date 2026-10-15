using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Delegation.Domain;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Delegation.Application.Features.Tokens;

/// <summary>Who may present an actor token for a delegated mint: a user in their own, interactive, non-PAT session.</summary>
internal static class ActorTokens
{
    public const string JsonClaimValueType = "JSON";

    public static Result<(Guid UserId, ClaimsPrincipal Principal)> Read(ExtensionGrantRequest request, ClaimNames names)
    {
        if (request.Actor is not { } actor)
        {
            return Error.Unauthorized(DelegationErrors.ActorRequired, "An actor_token (the acting user's access token) is required.");
        }

        var access = AccessContextReader.Read(actor, names);
        if (!AccessContextReader.IsInteractiveUser(actor, names) || access.UserId is not { } userId)
        {
            return Error.Unauthorized(DelegationErrors.ActorRequired, "The actor token must belong to a user.");
        }

        if (AccessContextReader.IsImpersonation(actor, names)
            || access.IsDelegated
            || actor.HasClaim(claim => claim.Type == names.DelegationScope)
            || actor.HasClaim(claim => claim.Type == names.PatCeiling || (claim.Type == names.CredentialType && claim.Value == "pat")))
        {
            return Error.Unauthorized(DelegationErrors.HomeSessionRequired, "Delegated tokens can only be minted from the actor's own interactive session.");
        }

        return (userId, actor);
    }

    public static void CopyAuthentication(ClaimsPrincipal actor, List<Claim> claims, ClaimNames names, bool includeMethods)
    {
        if (includeMethods)
        {
            claims.AddRange(actor.FindAll(names.AuthenticationMethods).Select(claim => new Claim(names.AuthenticationMethods, claim.Value)));
        }

        if (AccessContextReader.IsSteppedUp(actor, names))
        {
            claims.Add(new Claim(names.StepUp, names.StepUpSatisfied));
        }
    }

    public static Error Invalid(string message) => Error.Unauthorized(DelegationErrors.GrantInvalid, message);
}

/// <summary>
/// Mints an impersonation token: the target's identity with an RFC 8693 <c>act</c> claim naming the actor. Every mint
/// re-checks the grant, both accounts, the target's tenant and (for partners) the managing relationship, so ending any of them
/// stops access within one token lifetime. No refresh token: the client mints again.
/// </summary>
public sealed class MintImpersonationTokenHandler(
    IImpersonationGrantRepository grants,
    IAccountRepository accounts,
    IDelegationDirectory directory,
    SessionBuilder sessions,
    IDelegationUnitOfWork unitOfWork,
    ClaimNames names,
    IOptions<DelegationOptions> options,
    TimeProvider time) : IExtensionGrantHandler
{
    public const string GrantIdParameter = "grant_id";

    public string Name => DelegationOptions.ImpersonationGrant;

    public async Task<Result<IssuedIdentity>> HandleAsync(ExtensionGrantRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var actorToken = ActorTokens.Read(request, names);
        if (actorToken.IsFailure)
        {
            return actorToken.Error;
        }

        var (actorId, actor) = actorToken.Value;
        var now = time.GetUtcNow();

        if (!Guid.TryParse(request.Parameter(GrantIdParameter), out var grantId)
            || await grants.FindAsync(grantId, cancellationToken).ConfigureAwait(false) is not { } grant
            || grant.ActorUserId != actorId
            || !grant.CanMint(now))
        {
            return ActorTokens.Invalid("The impersonation grant is not approved, is over, or isn't yours.");
        }

        if (await accounts.FindAsync(actorId, cancellationToken).ConfigureAwait(false) is not { CanAuthenticate: true })
        {
            return ActorTokens.Invalid("Your account is not active.");
        }

        if (grant.ActorKind == ActorKind.Platform && !AccessContextReader.Read(actor, names).IsRoot)
        {
            return ActorTokens.Invalid("You are no longer a platform administrator.");
        }

        if (await accounts.FindAsync(grant.TargetUserId, cancellationToken).ConfigureAwait(false) is not { CanAuthenticate: true } target)
        {
            return ActorTokens.Invalid("The impersonated account is not active.");
        }

        var standing = grant.TargetTenantId is { } tenant
            ? await sessions.StandingAsync(target.Id, tenant, cancellationToken).ConfigureAwait(false)
            : Result.Success(TenantStanding.None);
        if (standing.IsFailure)
        {
            return standing.Error;
        }

        if (grant.ActorKind == ActorKind.Partner)
        {
            if (grant.ActorOrganizationId is not { } organization || grant.TargetTenantId is not { } managedTenant
                || AccessContextReader.Read(actor, names).OrganizationId != organization)
            {
                return ActorTokens.Invalid("The partner relationship no longer allows this.");
            }

            var scopes = await DirectoryCalls.ScopesAsync(directory, organization, managedTenant, cancellationToken).ConfigureAwait(false);
            if (scopes.IsFailure)
            {
                return scopes.Error;
            }

            if (scopes.Value.Count == 0)
            {
                return ActorTokens.Invalid("Your organization no longer manages this tenant.");
            }
        }

        if (!await RecordMintAsync(grant, now, cancellationToken).ConfigureAwait(false))
        {
            return ActorTokens.Invalid("The impersonation grant ended.");
        }

        var claims = new List<Claim>
        {
            new(names.Subject, target.Id.ToString()),
            new(names.Email, target.Email),
            new(names.Actor, JsonSerializer.Serialize(new Dictionary<string, string> { ["sub"] = actorId.ToString() }), ActorTokens.JsonClaimValueType),
            new(names.ActorKind, grant.ActorKind.ToString()),
            new(names.DelegationGrant, grant.Id.ToString()),
            new(names.AuthenticationTime, (grant.StartedAt ?? now).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
        };
        if (!string.IsNullOrEmpty(target.DisplayName))
        {
            claims.Add(new Claim(names.Name, target.DisplayName));
        }

        // Step-up reflects the actor's sign-in; the target's authentication methods are not claimed.
        ActorTokens.CopyAuthentication(actor, claims, names, includeMethods: false);
        sessions.AddTenantClaims(claims, standing.Value);

        var remaining = grant.ExpiresAt!.Value - now;
        var lifetime = options.Value.Impersonation.TokenLifetime;
        return new IssuedIdentity(target.Id.ToString(), claims, request.Scopes)
        {
            AccessTokenLifetime = remaining < lifetime ? remaining : lifetime,
            AllowRefresh = false,
        };
    }

    /// <summary>Records the mint; a concurrent first mint is joined, a concurrent end wins.</summary>
    private async Task<bool> RecordMintAsync(DelegationGrant grant, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (grant.StartedAt is not null)
        {
            return true;
        }

        grant.RecordMint(now);
        if (await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
        {
            return true;
        }

        await unitOfWork.ReloadAsync(grant, cancellationToken).ConfigureAwait(false);
        return grant.CanMint(now) && grant.StartedAt is not null;
    }
}

/// <summary>
/// Mints a tenant-switch token: the actor acting in a tenant their organization manages, with <c>lvl=Delegated</c>,
/// <c>act_tid</c> and the relationship's <c>dlg_scope</c> ceiling. A lockbox tenant also needs a live tenant-access grant.
/// Every mint re-checks it all. No refresh token: the client mints again.
/// </summary>
public sealed class MintTenantSwitchTokenHandler(
    ITenantAccessGrantRepository grants,
    IAccountRepository accounts,
    IDelegationDirectory directory,
    ITenantDirectory tenants,
    SessionBuilder sessions,
    IDelegationUnitOfWork unitOfWork,
    ClaimNames names,
    IOptions<DelegationOptions> options,
    TimeProvider time) : IExtensionGrantHandler
{
    public const string TargetTenantParameter = "target_tenant";

    public string Name => DelegationOptions.TenantSwitchGrant;

    public async Task<Result<IssuedIdentity>> HandleAsync(ExtensionGrantRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var actorToken = ActorTokens.Read(request, names);
        if (actorToken.IsFailure)
        {
            return actorToken.Error;
        }

        var (actorId, actor) = actorToken.Value;
        var access = AccessContextReader.Read(actor, names);
        var now = time.GetUtcNow();

        if (!Guid.TryParse(request.Parameter(TargetTenantParameter), out var target))
        {
            return ActorTokens.Invalid("A target_tenant is required.");
        }

        if (access.OrganizationId is not { } organization || access.TenantId is not { } home)
        {
            return Error.Unauthorized(DelegationErrors.OrganizationRequired, "Your session belongs to no organization.");
        }

        if (target == home)
        {
            return ActorTokens.Invalid("That is your own tenant.");
        }

        if (await accounts.FindAsync(actorId, cancellationToken).ConfigureAwait(false) is not { CanAuthenticate: true } account)
        {
            return ActorTokens.Invalid("Your account is not active.");
        }

        // The actor must still belong to the managing organization.
        var standing = await sessions.StandingAsync(actorId, home, cancellationToken).ConfigureAwait(false);
        if (standing.IsFailure)
        {
            return standing.Error;
        }

        if (standing.Value.OrganizationId != organization)
        {
            return ActorTokens.Invalid("You no longer belong to the managing organization.");
        }

        var scopes = await DirectoryCalls.ScopesAsync(directory, organization, target, cancellationToken).ConfigureAwait(false);
        if (scopes.IsFailure)
        {
            return scopes.Error;
        }

        if (scopes.Value.Count == 0)
        {
            return ActorTokens.Invalid("Your organization doesn't manage this tenant.");
        }

        var tenant = await DirectoryCalls.TenantAsync(tenants, target, cancellationToken).ConfigureAwait(false);
        if (tenant.IsFailure)
        {
            return tenant.Error;
        }

        if (tenant.Value is not { AcceptsSessions: true })
        {
            return Error.Unauthorized(GrantErrors.TenantInactive, "The tenant is not active.");
        }

        var lockbox = await DirectoryCalls.RequiresApprovalAsync(directory, target, cancellationToken).ConfigureAwait(false);
        if (lockbox.IsFailure)
        {
            return lockbox.Error;
        }

        DateTimeOffset? grantEnds = null;
        if (lockbox.Value)
        {
            var open = await grants.ListOpenAsync(actorId, target, now, cancellationToken).ConfigureAwait(false);
            var grant = open
                .Where(candidate => candidate.ActorUserId == actorId && candidate.TargetTenantId == target
                    && candidate.ActorOrganizationId == organization && candidate.CanMint(now))
                .OrderByDescending(candidate => candidate.ApprovedAt)
                .FirstOrDefault();
            if (grant is null || !await RecordMintAsync(grant, now, cancellationToken).ConfigureAwait(false))
            {
                return Error.Unauthorized(DelegationErrors.GrantInvalid, "This tenant requires approval and there is no approved access grant.");
            }

            grantEnds = grant.ExpiresAt;
        }

        var claims = new List<Claim>
        {
            new(names.Subject, actorId.ToString()),
            new(names.Email, account.Email),
            new(names.ActingTenant, target.ToString()),
        };
        if (!string.IsNullOrEmpty(account.DisplayName))
        {
            claims.Add(new Claim(names.Name, account.DisplayName));
        }

        if (actor.FindFirst(names.AuthenticationTime) is { } authTime)
        {
            claims.Add(new Claim(names.AuthenticationTime, authTime.Value, ClaimValueTypes.Integer64));
        }

        ActorTokens.CopyAuthentication(actor, claims, names, includeMethods: true);
        sessions.AddTenantClaims(claims, standing.Value);
        claims.RemoveAll(claim => claim.Type == names.Level);
        claims.Add(new Claim(names.Level, nameof(AccessLevel.Delegated)));
        claims.AddRange(scopes.Value.Distinct(StringComparer.OrdinalIgnoreCase).Select(scope => new Claim(names.DelegationScope, scope.ToLowerInvariant())));

        var lifetime = options.Value.TenantAccess.TokenLifetime;
        if (grantEnds is { } ends && ends - now < lifetime)
        {
            lifetime = ends - now;
        }

        return new IssuedIdentity(actorId.ToString(), claims, request.Scopes)
        {
            AccessTokenLifetime = lifetime,
            AllowRefresh = false,
        };
    }

    private async Task<bool> RecordMintAsync(DelegationGrant grant, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (grant.StartedAt is not null)
        {
            return true;
        }

        grant.RecordMint(now);
        if (await unitOfWork.TrySaveChangesAsync(cancellationToken).ConfigureAwait(false))
        {
            return true;
        }

        await unitOfWork.ReloadAsync(grant, cancellationToken).ConfigureAwait(false);
        return grant.CanMint(now) && grant.StartedAt is not null;
    }
}

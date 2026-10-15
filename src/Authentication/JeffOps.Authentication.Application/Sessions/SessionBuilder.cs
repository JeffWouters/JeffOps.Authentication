using System.Globalization;
using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Application.Sessions;

/// <summary>The tenant a session is issued in, with what the directory said about it.</summary>
public sealed record TenantStanding(TenantMembership? Membership, TenantInfo? Tenant)
{
    public static TenantStanding None { get; } = new(null, null);

    public Guid? OrganizationId => Membership?.OrganizationId ?? Tenant?.OrganizationId;
}

/// <summary>
/// Builds session claims from live state: the account, its authentication strength and its tenant standing. Every grant that
/// issues a user token goes through here, so claims are never copied from an older token (docs/DESIGN.md §7.6).
/// </summary>
public sealed class SessionBuilder(ITenantDirectory tenants, ClaimNames names, IOptions<TokenServerOptions> options)
{
    private MfaPolicy Mfa => new(options.Value.Mfa.RequireForSignIn, options.Value.Mfa.RequireForSensitiveActions);

    /// <summary>
    /// The account's tenant standing: in <paramref name="boundTenant"/> when given (it must still hold an active membership
    /// there), otherwise in its first membership whose tenant accepts sessions. No memberships at all is a valid, tenant-less
    /// session.
    /// </summary>
    public async Task<Result<TenantStanding>> StandingAsync(Guid accountId, Guid? boundTenant, CancellationToken cancellationToken)
    {
        IReadOnlyList<TenantMembership> memberships;
        try
        {
            memberships = await tenants.GetMembershipsAsync(accountId, cancellationToken).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // Any directory failure is an outage, reported so clients retry rather than sign out.
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
        {
            return Unavailable();
        }

        if (boundTenant is { } bound)
        {
            var held = memberships.FirstOrDefault(membership => membership.TenantId == bound);
            if (held is null)
            {
                return Error.Unauthorized(GrantErrors.NoMembership, "The account no longer has a membership in this tenant.");
            }

            return await StandingInAsync(held, cancellationToken).ConfigureAwait(false);
        }

        foreach (var membership in memberships)
        {
            var standing = await StandingInAsync(membership, cancellationToken).ConfigureAwait(false);
            if (standing.IsSuccess || standing.Error.Type == ErrorType.Unavailable)
            {
                return standing;
            }
        }

        return memberships.Count == 0
            ? TenantStanding.None
            : Error.Unauthorized(GrantErrors.TenantInactive, "The account's tenant is no longer active.");
    }

    /// <summary>The claims of an interactive user session.</summary>
    public List<Claim> UserClaims(Account account, AuthenticationStrength strength, DateTimeOffset signedInAt, TenantStanding standing)
    {
        ArgumentNullException.ThrowIfNull(account);
        ArgumentNullException.ThrowIfNull(strength);
        ArgumentNullException.ThrowIfNull(standing);

        var claims = new List<Claim>
        {
            new(names.Subject, account.Id.ToString()),
            new(names.Email, account.Email),
            new(names.AuthenticationTime, signedInAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64),
        };

        if (!string.IsNullOrEmpty(account.DisplayName))
        {
            claims.Add(new Claim(names.Name, account.DisplayName));
        }

        claims.AddRange(strength.Methods.Select(method => new Claim(names.AuthenticationMethods, method)));
        if (Mfa.SatisfiesStepUp(strength))
        {
            claims.Add(new Claim(names.StepUp, names.StepUpSatisfied));
        }

        AddTenantClaims(claims, standing);
        return claims;
    }

    public void AddTenantClaims(List<Claim> claims, TenantStanding standing)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(standing);

        claims.Add(new Claim(names.Level, (standing.Membership?.Level ?? AccessLevel.Tenant).ToString()));
        if (standing.Membership is { } membership)
        {
            claims.Add(new Claim(names.Tenant, membership.TenantId.ToString()));
            if (membership.WorkspaceId is { } workspace)
            {
                claims.Add(new Claim(names.Workspace, workspace.ToString()));
            }
        }

        if (standing.OrganizationId is { } organization)
        {
            claims.Add(new Claim(names.Organization, organization.ToString()));
        }
    }

    public bool AllowsSignIn(AuthenticationStrength strength) => Mfa.AllowsSignIn(strength);

    public bool SatisfiesStepUp(AuthenticationStrength strength) => Mfa.SatisfiesStepUp(strength);

    private async Task<Result<TenantStanding>> StandingInAsync(TenantMembership membership, CancellationToken cancellationToken)
    {
        TenantInfo? tenant;
        try
        {
            tenant = await tenants.FindTenantAsync(membership.TenantId, cancellationToken).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // See StandingAsync.
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
        {
            return Unavailable();
        }

        return tenant is { AcceptsSessions: true }
            ? new TenantStanding(membership, tenant)
            : Error.Unauthorized(GrantErrors.TenantInactive, "The account's tenant is no longer active.");
    }

    private static Error Unavailable() =>
        Error.Unavailable(GrantErrors.DirectoryUnavailable, "The tenant directory is unavailable. Try again.");
}

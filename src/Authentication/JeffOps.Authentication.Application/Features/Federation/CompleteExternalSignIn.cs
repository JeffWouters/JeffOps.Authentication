using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.Sessions;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Application.Features.Federation.CompleteExternalSignIn;

/// <summary>Completes a sign-in at an external provider: finds or creates the linked account.</summary>
public sealed record CompleteExternalSignInCommand(ExternalIdentity Identity);

/// <summary>The account to sign in, and how strongly the user authenticated.</summary>
public sealed record ExternalSignInResult(Guid AccountId, AuthenticationStrength Strength, bool IsNewAccount);

public static class FederationErrors
{
    public const string DomainNotAllowed = "domain_not_allowed";
    public const string RegistrationClosed = "registration_closed";
    public const string EmailRequired = "email_required";
    public const string SsoRequired = "sso_required";
    public const string LinkRequired = "link_required";
}

/// <summary>
/// Links by (issuer, subject) — not by email in general, so a provider that lets users change their address can't be used to
/// take over another account (docs/DESIGN.md §8.2). One exception, where the tenant vouches for both sides: the first
/// sign-in through a tenant's own SSO provider, with a verified email in the tenant's verified domain, claims the account
/// that tenant's provisioning (SCIM) created or linked for that address, if it has no login from this provider yet. New
/// accounts are created just in time when allowed. The email-domain policy applies to every external sign-in, not only the
/// first, so removing a domain locks its users out at their next sign-in.
/// </summary>
public sealed class CompleteExternalSignInHandler(
    IAccountRepository accounts,
    IUnitOfWork unitOfWork,
    SessionBuilder sessions,
    IEnumerable<IExternalSignInObserver> observers,
    IHomeRealmDirectory realms,
    IProvisionedAccountDirectory provisioned,
    IAccountCredentials credentials,
    IPendingLinks pendingLinks,
    JeffOps.Authentication.Abstractions.Tenancy.ITenantDirectory tenants,
    IAuditSink audit,
    IOptions<FederationOptions> options,
    IHostEnvironment environment,
    TimeProvider time) : ICommandHandler<CompleteExternalSignInCommand, ExternalSignInResult>
{
    public async Task<Result<ExternalSignInResult>> HandleAsync(CompleteExternalSignInCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var identity = command.Identity;
        var settings = options.Value;
        var now = time.GetUtcNow();

        var existing = await accounts.FindByExternalLoginAsync(identity.Login, cancellationToken).ConfigureAwait(false);
        var domain = HomeRealm.DomainOf(identity.Email);
        var realm = domain is null ? null : await realms.FindByDomainAsync(domain, cancellationToken).ConfigureAwait(false);
        if (realm is { SsoOnly: true } && !string.Equals(realm.Provider, identity.Provider, StringComparison.OrdinalIgnoreCase)
            && !pendingLinks.Confirms(existing?.Id, realm))
        {
            await AuditRefusalAsync(identity, FederationErrors.SsoRequired, now, cancellationToken).ConfigureAwait(false);
            return Error.Forbidden(FederationErrors.SsoRequired, "Your organization requires signing in with its own identity provider.");
        }

        // A tenant's verified domain admits its members through the tenant's own provider.
        var admittedByTenant = realm is { Provider: { } realmProvider } && identity.EmailVerified
            && string.Equals(realmProvider, identity.Provider, StringComparison.OrdinalIgnoreCase);
        if (!admittedByTenant && !DomainAllowed(identity, settings))
        {
            await AuditRefusalAsync(identity, FederationErrors.DomainNotAllowed, now, cancellationToken).ConfigureAwait(false);
            return Error.Forbidden(FederationErrors.DomainNotAllowed, "This account's email domain is not permitted to sign in.");
        }

        if (!sessions.AllowsSignIn(identity.Strength))
        {
            await AuditRefusalAsync(identity, GrantErrors.MfaRequired, now, cancellationToken).ConfigureAwait(false);
            return Error.Forbidden(GrantErrors.MfaRequired, "This platform requires a multi-factor sign-in.");
        }

        var account = existing;
        if (account is null && admittedByTenant && realm is not null)
        {
            var (claimed, toConfirm) = await ClaimProvisionedAsync(realm.TenantId, identity, now, cancellationToken).ConfigureAwait(false);
            if (toConfirm is { } existingAccount)
            {
                // An account the tenant didn't create, or one with other credentials or other tenants: its owner confirms the
                // new login by signing in their usual way first (docs/DESIGN.md §8.2).
                pendingLinks.Set(new PendingLink(existingAccount, identity.Login.Issuer, identity.Login.Subject, identity.Provider, now + PendingLinkLifetime));
                await AuditRefusalAsync(identity, FederationErrors.LinkRequired, now, cancellationToken).ConfigureAwait(false);
                return Error.Forbidden(FederationErrors.LinkRequired, "Sign in the way you usually do once, to link this sign-in to your account.");
            }

            account = claimed;
        }

        var isNew = account is null;
        if (account is null)
        {
            if (!settings.AutoProvisionAccounts)
            {
                return Error.Forbidden(FederationErrors.RegistrationClosed, "There is no account for this sign-in.");
            }

            if (string.IsNullOrWhiteSpace(identity.Email))
            {
                return Error.Forbidden(FederationErrors.EmailRequired, "The provider did not report an email address.");
            }

            account = Account.RegisterExternal(identity.Email, identity.DisplayName ?? identity.Email, identity.Login, identity.Provider, now, identity.EmailVerified);
            accounts.Add(account);
        }
        else
        {
            account.UpdateProfile(identity.EmailVerified ? identity.Email : null, identity.DisplayName, now);
        }

        if (!account.CanAuthenticate)
        {
            return Error.Unauthorized(GrantErrors.AccountInactive, "This account is not active.");
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        foreach (var observer in observers)
        {
            await observer.OnSignedInAsync(account.Id, identity, isNew, cancellationToken).ConfigureAwait(false);
        }

        return new ExternalSignInResult(account.Id, identity.Strength, isNew);
    }

    /// <summary>How long a pending link waits for its owner's confirmation.</summary>
    internal static readonly TimeSpan PendingLinkLifetime = TimeSpan.FromMinutes(10);

    /// <summary>
    /// The account the tenant's provisioning holds for this email. Claimed (linked to this login) only when provisioning created
    /// it and it has nothing else: no other login, no credentials of its own, no membership in another tenant. Any other
    /// existing account is returned for its owner to confirm; a tenant's provider never silently takes over an account that
    /// may belong to someone with other sign-ins, tenants or administrative roles.
    /// </summary>
    private async Task<(Account? Claimed, Guid? ToConfirm)> ClaimProvisionedAsync(Guid tenantId, ExternalIdentity identity, DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(identity.Email)
            || await provisioned.FindAsync(tenantId, identity.Email, cancellationToken).ConfigureAwait(false) is not { } held
            || await accounts.FindAsync(held.AccountId, cancellationToken).ConfigureAwait(false) is not { } account
            || !string.Equals(account.Email, Account.NormalizeEmail(identity.Email), StringComparison.Ordinal)
            || account.ExternalLogins.Any(login => string.Equals(login.Issuer, identity.Login.Issuer, StringComparison.Ordinal)))
        {
            return (null, null);
        }

        if (!held.CreatedByProvisioning
            || account.ExternalLogins.Count > 0
            || await credentials.HasLocalCredentialsAsync(account.Id, cancellationToken).ConfigureAwait(false)
            || await HasOtherMembershipsAsync(account.Id, tenantId, cancellationToken).ConfigureAwait(false))
        {
            return (null, account.Id);
        }

        account.LinkExternalLogin(identity.Login, identity.Provider, now);
        await audit.WriteAsync(
            new AuditRecord("signin.provisioned_account_linked", "account", account.Id.ToString())
            {
                OccurredAt = now,
                TenantId = tenantId,
                Details = new Dictionary<string, string?> { ["provider"] = identity.Provider, ["issuer"] = identity.Login.Issuer },
            },
            cancellationToken).ConfigureAwait(false);
        return (account, null);
    }

    /// <summary>Whether the account belongs to any tenant besides <paramref name="tenantId"/>; an outage counts as yes (confirm rather than claim).</summary>
    private async Task<bool> HasOtherMembershipsAsync(Guid accountId, Guid tenantId, CancellationToken cancellationToken)
    {
        try
        {
            return (await tenants.GetMembershipsAsync(accountId, cancellationToken).ConfigureAwait(false)).Any(membership => membership.TenantId != tenantId);
        }
#pragma warning disable CA1031 // Fail safe: an unknown standing is treated as one that needs the owner's confirmation.
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
        {
            return true;
        }
    }

    // Only an address the provider vouches for counts: an unverified one is whatever the user typed in their own directory.
    private bool DomainAllowed(ExternalIdentity identity, FederationOptions settings) =>
        settings.AllowsEmailDomain(identity.Email, identity.EmailVerified, environment.IsDevelopment());

    private Task AuditRefusalAsync(ExternalIdentity identity, string reason, DateTimeOffset now, CancellationToken cancellationToken) =>
        audit.WriteAsync(
            new AuditRecord("signin.refused", "external_login", $"{identity.Login.Issuer}|{identity.Login.Subject}")
            {
                OccurredAt = now,
                Severity = AuditSeverity.Warning,
                Details = new Dictionary<string, string?> { ["provider"] = identity.Provider, ["reason"] = reason },
            },
            cancellationToken);
}

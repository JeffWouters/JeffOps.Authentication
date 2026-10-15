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
}

/// <summary>
/// Links by (issuer, subject) only — never by email, so a provider that lets users change their address can't be used to
/// take over another account (docs/DESIGN.md §8.2). New accounts are created just in time when allowed. The email-domain
/// policy applies to every external sign-in, not only the first, so removing a domain locks its users out at their next
/// sign-in.
/// </summary>
public sealed class CompleteExternalSignInHandler(
    IAccountRepository accounts,
    IUnitOfWork unitOfWork,
    SessionBuilder sessions,
    IEnumerable<IExternalSignInObserver> observers,
    IHomeRealmDirectory realms,
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

        var domain = HomeRealm.DomainOf(identity.Email);
        var realm = domain is null ? null : await realms.FindByDomainAsync(domain, cancellationToken).ConfigureAwait(false);
        if (realm is { SsoOnly: true } && !string.Equals(realm.Provider, identity.Provider, StringComparison.OrdinalIgnoreCase))
        {
            await AuditRefusalAsync(identity, FederationErrors.SsoRequired, now, cancellationToken).ConfigureAwait(false);
            return Error.Forbidden(FederationErrors.SsoRequired, "Your organization requires signing in with its own identity provider.");
        }

        // A tenant's verified domain admits its members through the tenant's own provider.
        var admittedByTenant = realm is { Provider: { } realmProvider } && identity.EmailVerified
            && string.Equals(realmProvider, identity.Provider, StringComparison.OrdinalIgnoreCase);
        if (!admittedByTenant && !DomainAllowed(identity.Email, settings))
        {
            await AuditRefusalAsync(identity, FederationErrors.DomainNotAllowed, now, cancellationToken).ConfigureAwait(false);
            return Error.Forbidden(FederationErrors.DomainNotAllowed, "This account's email domain is not permitted to sign in.");
        }

        if (!sessions.AllowsSignIn(identity.Strength))
        {
            await AuditRefusalAsync(identity, GrantErrors.MfaRequired, now, cancellationToken).ConfigureAwait(false);
            return Error.Forbidden(GrantErrors.MfaRequired, "This platform requires a multi-factor sign-in.");
        }

        var account = await accounts.FindByExternalLoginAsync(identity.Login, cancellationToken).ConfigureAwait(false);
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

    private bool DomainAllowed(string? email, FederationOptions settings)
    {
        if (settings.AllowedEmailDomains.Count == 0)
        {
            return settings.OpenRegistration ?? environment.IsDevelopment();
        }

        var domain = HomeRealm.DomainOf(email);
        return domain is not null && settings.AllowedEmailDomains.Any(allowed =>
            string.Equals(allowed.Trim().TrimStart('@'), domain, StringComparison.OrdinalIgnoreCase));
    }

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

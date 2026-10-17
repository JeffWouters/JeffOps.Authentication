using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Enterprise.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Enterprise.Application.Features.Providers;

/// <summary>
/// A tenant's own OpenID Connect provider. <c>Name</c> is what sign-in URLs use (select it as the tenant's SSO provider to use
/// it); <c>RedirectPath</c>, <c>PostLogoutRedirectPath</c> and <c>BackchannelLogoutPath</c> are the URIs to register at the
/// provider, relative to the token server. The client secret is never returned: <c>HasClientSecret</c> says whether one is stored.
/// </summary>
public sealed record TenantOidcProviderDto(
    Guid Id,
    string Name,
    string DisplayName,
    string Issuer,
    string ClientId,
    bool HasClientSecret,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> MultiFactorAcrValues,
    string RedirectPath,
    string PostLogoutRedirectPath,
    string BackchannelLogoutPath,
    DateTimeOffset UpdatedAt);

/// <summary>
/// A tenant OIDC provider's settings, as an administrator submits them. On a change, a null or empty
/// <c>ClientSecret</c> keeps the stored one; <c>RemoveClientSecret</c> removes it.
/// </summary>
public sealed record TenantOidcProviderData(
    string? DisplayName,
    string? Issuer,
    string? ClientId,
    string? ClientSecret,
    bool RemoveClientSecret,
    IReadOnlyList<string>? Scopes,
    IReadOnlyList<string>? MultiFactorAcrValues);

internal static class TenantOidcProviderRules
{
    public static TenantOidcProviderDto ToDto(this TenantOidcIdentityProvider provider) => new(
        provider.Id, provider.Name, provider.DisplayName, provider.Issuer, provider.ClientId, provider.ProtectedClientSecret is not null,
        provider.ScopeList, provider.MultiFactorAcrValueList, $"signin/oidc/{provider.Name}/callback",
        $"signin/oidc/{provider.Name}/signed-out", $"signin/oidc/{provider.Name}/backchannel-logout", provider.UpdatedAt);

    /// <summary>
    /// Refuses settings that can't work or aren't safe: the issuer is an <c>https://</c> URL naming a host, not an IP address
    /// (the server reads its discovery document and keys itself, and checks every connection again); a client id; scopes in
    /// the OAuth syntax.
    /// </summary>
    public static Error? Check(TenantOidcProviderData data)
    {
        var failures = new List<ValidationFailure>();
        if (string.IsNullOrWhiteSpace(data.DisplayName) || data.DisplayName.Trim().Length > 100)
        {
            failures.Add(new ValidationFailure("displayName", "A display name of at most 100 characters is required."));
        }

        if (string.IsNullOrWhiteSpace(data.Issuer) || data.Issuer.Trim().Length > 512 || !TenantProviderRules.IsHttpsHost(data.Issuer) || data.Issuer.Contains('?', StringComparison.Ordinal) || data.Issuer.Contains('#', StringComparison.Ordinal))
        {
            failures.Add(new ValidationFailure("issuer", "The provider's issuer is required: an https:// URL with a host name, no query or fragment."));
        }

        if (string.IsNullOrWhiteSpace(data.ClientId) || data.ClientId.Trim().Length > 256)
        {
            failures.Add(new ValidationFailure("clientId", "The client id (at most 256 characters) is required."));
        }

        if (data.ClientSecret is { Length: > 1024 })
        {
            failures.Add(new ValidationFailure("clientSecret", "The client secret is at most 1024 characters."));
        }

        var scopes = data.Scopes ?? [];
        if (scopes.Count > 10 || scopes.Any(scope => scope.Trim().Length is 0 or > 100 || scope.Trim().Any(character => character <= ' ' || character is '"' or '\\' || character > '~')))
        {
            failures.Add(new ValidationFailure("scopes", "Give at most ten scopes, each without spaces, quotes or backslashes."));
        }

        var contexts = data.MultiFactorAcrValues ?? [];
        if (contexts.Count > 10 || contexts.Any(context => context.Trim().Length is 0 or > 256))
        {
            failures.Add(new ValidationFailure("multiFactorAcrValues", "Give at most ten authentication context values of at most 256 characters."));
        }

        return failures.Count == 0 ? null : Error.Validation(failures);
    }
}

public sealed record ListTenantOidcProvidersQuery(EnterpriseCaller Caller);

public sealed class ListTenantOidcProvidersHandler(ITenantOidcProviderRepository providers) : IQueryHandler<ListTenantOidcProvidersQuery, IReadOnlyList<TenantOidcProviderDto>>
{
    public async Task<Result<IReadOnlyList<TenantOidcProviderDto>>> HandleAsync(ListTenantOidcProvidersQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        return (await providers.ListForTenantAsync(query.Caller.TenantId, cancellationToken).ConfigureAwait(false)).Select(provider => provider.ToDto()).ToList();
    }
}

/// <summary>Adds (with <c>ProviderId</c> null) or changes one of the tenant's own OpenID Connect providers.</summary>
public sealed record SaveTenantOidcProviderCommand(EnterpriseCaller Caller, Guid? ProviderId, TenantOidcProviderData Data);

public sealed class SaveTenantOidcProviderHandler(
    ITenantOidcProviderRepository providers,
    ITenantIdentityProviderRepository samlProviders,
    ISsoPolicyRepository policies,
    IClientSecretProtector secrets,
    IEnterpriseUnitOfWork unitOfWork,
    IAuditSink audit,
    IOptions<EnterpriseOptions> options,
    TimeProvider time) : ICommandHandler<SaveTenantOidcProviderCommand, TenantOidcProviderDto>
{
    public async Task<Result<TenantOidcProviderDto>> HandleAsync(SaveTenantOidcProviderCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var tenantId = command.Caller.TenantId;
        if (await policies.FindAsync(tenantId, cancellationToken).ConfigureAwait(false) is not { CustomProvidersAllowed: true })
        {
            return Error.Forbidden(EnterpriseErrors.CustomProvidersNotAllowed, "This tenant can't register its own identity providers. Ask the platform operator.");
        }

        if (TenantOidcProviderRules.Check(command.Data) is { } invalid)
        {
            return invalid;
        }

        var now = time.GetUtcNow();
        TenantOidcIdentityProvider provider;
        if (command.ProviderId is { } id)
        {
            if (await providers.FindAsync(id, cancellationToken).ConfigureAwait(false) is not { } existing || existing.TenantId != tenantId)
            {
                return Error.NotFound(EnterpriseErrors.NotFound, "No such provider.");
            }

            provider = existing;
        }
        else
        {
            var count = (await providers.ListForTenantAsync(tenantId, cancellationToken).ConfigureAwait(false)).Count
                + (await samlProviders.ListForTenantAsync(tenantId, cancellationToken).ConfigureAwait(false)).Count;
            if (count >= options.Value.MaxProvidersPerTenant)
            {
                return Error.Failure(EnterpriseErrors.TooManyProviders, $"A tenant can have at most {options.Value.MaxProvidersPerTenant} providers.");
            }

            provider = TenantOidcIdentityProvider.Create(tenantId, now);
            providers.Add(provider);
        }

        var data = command.Data;
        provider.Set(data.DisplayName!, data.Issuer!, data.ClientId!, data.Scopes ?? [], data.MultiFactorAcrValues ?? [], command.Caller.UserId, now);
        var secretChanged = false;
        if (!string.IsNullOrEmpty(data.ClientSecret))
        {
            provider.SetClientSecret(secrets.Protect(data.ClientSecret), command.Caller.UserId, now);
            secretChanged = true;
        }
        else if (data.RemoveClientSecret && provider.ProtectedClientSecret is not null)
        {
            provider.SetClientSecret(null, command.Caller.UserId, now);
            secretChanged = true;
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord(command.ProviderId is null ? "tenant_oidc_provider.created" : "tenant_oidc_provider.changed", "tenant_oidc_provider", provider.Id.ToString())
        {
            ActorId = command.Caller.UserId,
            TenantId = tenantId,
            OccurredAt = now,
            Severity = AuditSeverity.Warning,
            Details = new Dictionary<string, string?>
            {
                ["issuer"] = provider.Issuer,
                ["clientId"] = provider.ClientId,
                ["clientSecretChanged"] = secretChanged ? "true" : "false",
            },
        }, cancellationToken).ConfigureAwait(false);
        return provider.ToDto();
    }
}

public sealed record DeleteTenantOidcProviderCommand(EnterpriseCaller Caller, Guid ProviderId);

/// <summary>Removes a tenant OIDC provider; a tenant whose SSO policy names it falls back to no provider.</summary>
public sealed class DeleteTenantOidcProviderHandler(
    ITenantOidcProviderRepository providers,
    ISsoPolicyRepository policies,
    IEnterpriseUnitOfWork unitOfWork,
    IAuditSink audit,
    TimeProvider time) : ICommandHandler<DeleteTenantOidcProviderCommand>
{
    public async Task<Result> HandleAsync(DeleteTenantOidcProviderCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (await providers.FindAsync(command.ProviderId, cancellationToken).ConfigureAwait(false) is not { } provider || provider.TenantId != command.Caller.TenantId)
        {
            return Error.NotFound(EnterpriseErrors.NotFound, "No such provider.");
        }

        var now = time.GetUtcNow();
        if (await policies.FindAsync(provider.TenantId, cancellationToken).ConfigureAwait(false) is { } policy
            && string.Equals(policy.Provider, provider.Name, StringComparison.Ordinal))
        {
            policy.Set(null, ssoOnly: false, command.Caller.UserId, now);
        }

        providers.Remove(provider);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("tenant_oidc_provider.removed", "tenant_oidc_provider", provider.Id.ToString())
        {
            ActorId = command.Caller.UserId,
            TenantId = provider.TenantId,
            OccurredAt = now,
            Severity = AuditSeverity.Warning,
        }, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Enterprise.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Enterprise.Application.Features.Providers;

/// <summary>
/// A tenant's own SAML provider. <c>Name</c> is what sign-in URLs use (select it as the tenant's SSO provider to use it);
/// <c>ServiceProviderMetadataPath</c> is this server's metadata to give the provider, relative to the token server.
/// </summary>
public sealed record TenantProviderDto(
    Guid Id,
    string Name,
    string DisplayName,
    string EntityId,
    string? MetadataUrl,
    string? SingleSignOnUrl,
    string? SingleLogoutUrl,
    IReadOnlyList<string> SigningCertificates,
    IReadOnlyList<string> MultiFactorAuthnContexts,
    string ServiceProviderMetadataPath,
    DateTimeOffset UpdatedAt);

/// <summary>A tenant provider's settings, as an administrator submits them.</summary>
public sealed record TenantProviderData(
    string? DisplayName,
    string? EntityId,
    string? MetadataUrl,
    string? SingleSignOnUrl,
    string? SingleLogoutUrl,
    IReadOnlyList<string>? SigningCertificates,
    IReadOnlyList<string>? MultiFactorAuthnContexts);

internal static class TenantProviderRules
{
    public static TenantProviderDto ToDto(this TenantIdentityProvider provider) => new(
        provider.Id, provider.Name, provider.DisplayName, provider.EntityId, provider.MetadataUrl, provider.SingleSignOnUrl, provider.SingleLogoutUrl,
        provider.CertificateList, provider.MultiFactorAuthnContextList, $"signin/saml/{provider.Name}/metadata", provider.UpdatedAt);

    /// <summary>
    /// Refuses settings that can't work or aren't safe: a provider needs an entity id, and either its metadata URL or its
    /// sign-in URL with a signing certificate; every URL is HTTPS and names a host, not an IP address (the server fetches
    /// metadata itself, and checks every connection again).
    /// </summary>
    public static Error? Check(TenantProviderData data)
    {
        var failures = new List<ValidationFailure>();
        if (string.IsNullOrWhiteSpace(data.DisplayName) || data.DisplayName.Trim().Length > 100)
        {
            failures.Add(new ValidationFailure("displayName", "A display name of at most 100 characters is required."));
        }

        if (string.IsNullOrWhiteSpace(data.EntityId) || data.EntityId.Trim().Length > 512)
        {
            failures.Add(new ValidationFailure("entityId", "The provider's entity id (at most 512 characters) is required."));
        }

        foreach (var (name, url) in new[] { ("metadataUrl", data.MetadataUrl), ("singleSignOnUrl", data.SingleSignOnUrl), ("singleLogoutUrl", data.SingleLogoutUrl) })
        {
            if (!string.IsNullOrWhiteSpace(url) && !IsHttpsHost(url))
            {
                failures.Add(new ValidationFailure(name, "Use an https:// URL with a host name."));
            }
        }

        var certificates = data.SigningCertificates ?? [];
        if (certificates.Count > 5 || certificates.Any(certificate => !Parses(certificate)))
        {
            failures.Add(new ValidationFailure("signingCertificates", "Give at most five signing certificates, base64 DER or PEM."));
        }

        if (string.IsNullOrWhiteSpace(data.MetadataUrl) && (string.IsNullOrWhiteSpace(data.SingleSignOnUrl) || certificates.Count == 0))
        {
            failures.Add(new ValidationFailure("metadataUrl", "Give the provider's metadata URL, or its sign-in URL and a signing certificate."));
        }

        return failures.Count == 0 ? null : Error.Validation(failures);
    }

    internal static bool IsHttpsHost(string url) =>
        Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps
        && uri.HostNameType == UriHostNameType.Dns && !IPAddress.TryParse(uri.Host, out _) && uri.Host.Contains('.', StringComparison.Ordinal);

    private static bool Parses(string certificate)
    {
        try
        {
            var trimmed = certificate.Trim();
            using var loaded = trimmed.StartsWith("-----BEGIN", StringComparison.Ordinal)
                ? X509Certificate2.CreateFromPem(trimmed)
                : X509CertificateLoader.LoadCertificate(Convert.FromBase64String(trimmed));
            return true;
        }
        catch (Exception exception) when (exception is FormatException or CryptographicException or ArgumentException)
        {
            return false;
        }
    }
}

public sealed record ListTenantProvidersQuery(EnterpriseCaller Caller);

public sealed class ListTenantProvidersHandler(ITenantIdentityProviderRepository providers) : IQueryHandler<ListTenantProvidersQuery, IReadOnlyList<TenantProviderDto>>
{
    public async Task<Result<IReadOnlyList<TenantProviderDto>>> HandleAsync(ListTenantProvidersQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        return (await providers.ListForTenantAsync(query.Caller.TenantId, cancellationToken).ConfigureAwait(false)).Select(provider => provider.ToDto()).ToList();
    }
}

/// <summary>Adds (with <c>ProviderId</c> null) or changes one of the tenant's own SAML providers.</summary>
public sealed record SaveTenantProviderCommand(EnterpriseCaller Caller, Guid? ProviderId, TenantProviderData Data);

public sealed class SaveTenantProviderHandler(
    ITenantIdentityProviderRepository providers,
    ITenantOidcProviderRepository oidcProviders,
    ISsoPolicyRepository policies,
    IEnterpriseUnitOfWork unitOfWork,
    IAuditSink audit,
    IOptions<EnterpriseOptions> options,
    TimeProvider time) : ICommandHandler<SaveTenantProviderCommand, TenantProviderDto>
{
    public async Task<Result<TenantProviderDto>> HandleAsync(SaveTenantProviderCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var tenantId = command.Caller.TenantId;
        if (await policies.FindAsync(tenantId, cancellationToken).ConfigureAwait(false) is not { CustomProvidersAllowed: true })
        {
            return Error.Forbidden(EnterpriseErrors.CustomProvidersNotAllowed, "This tenant can't register its own identity providers. Ask the platform operator.");
        }

        if (TenantProviderRules.Check(command.Data) is { } invalid)
        {
            return invalid;
        }

        var now = time.GetUtcNow();
        TenantIdentityProvider provider;
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
                + (await oidcProviders.ListForTenantAsync(tenantId, cancellationToken).ConfigureAwait(false)).Count;
            if (count >= options.Value.MaxProvidersPerTenant)
            {
                return Error.Failure(EnterpriseErrors.TooManyProviders, $"A tenant can have at most {options.Value.MaxProvidersPerTenant} providers.");
            }

            provider = TenantIdentityProvider.Create(tenantId, now);
            providers.Add(provider);
        }

        var data = command.Data;
        provider.Set(data.DisplayName!, data.EntityId!, data.MetadataUrl, data.SingleSignOnUrl, data.SingleLogoutUrl,
            data.SigningCertificates ?? [], data.MultiFactorAuthnContexts ?? [], command.Caller.UserId, now);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord(command.ProviderId is null ? "tenant_provider.created" : "tenant_provider.changed", "tenant_provider", provider.Id.ToString())
        {
            ActorId = command.Caller.UserId,
            TenantId = tenantId,
            OccurredAt = now,
            Severity = AuditSeverity.Warning,
            Details = new Dictionary<string, string?> { ["entityId"] = provider.EntityId, ["metadataUrl"] = provider.MetadataUrl },
        }, cancellationToken).ConfigureAwait(false);
        return provider.ToDto();
    }
}

public sealed record DeleteTenantProviderCommand(EnterpriseCaller Caller, Guid ProviderId);

/// <summary>Removes a tenant provider; a tenant whose SSO policy names it falls back to no provider.</summary>
public sealed class DeleteTenantProviderHandler(
    ITenantIdentityProviderRepository providers,
    ISsoPolicyRepository policies,
    IEnterpriseUnitOfWork unitOfWork,
    IAuditSink audit,
    TimeProvider time) : ICommandHandler<DeleteTenantProviderCommand>
{
    public async Task<Result> HandleAsync(DeleteTenantProviderCommand command, CancellationToken cancellationToken)
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
        await audit.WriteAsync(new AuditRecord("tenant_provider.removed", "tenant_provider", provider.Id.ToString())
        {
            ActorId = command.Caller.UserId,
            TenantId = provider.TenantId,
            OccurredAt = now,
            Severity = AuditSeverity.Warning,
        }, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

/// <summary>A platform operator allows (or stops) a tenant registering its own identity providers.</summary>
public sealed record SetCustomProvidersAllowedCommand(Guid OperatorId, Guid TenantId, bool Allowed);

public sealed class SetCustomProvidersAllowedHandler(ISsoPolicyRepository policies, IEnterpriseUnitOfWork unitOfWork, IAuditSink audit, TimeProvider time)
    : ICommandHandler<SetCustomProvidersAllowedCommand>
{
    public async Task<Result> HandleAsync(SetCustomProvidersAllowedCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var now = time.GetUtcNow();
        var policy = await policies.FindAsync(command.TenantId, cancellationToken).ConfigureAwait(false);
        if (policy is null)
        {
            policy = SsoPolicy.For(command.TenantId);
            policies.Add(policy);
        }

        policy.AllowCustomProviders(command.Allowed, command.OperatorId, now);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord(command.Allowed ? "tenant_providers.allowed" : "tenant_providers.disallowed", "tenant", command.TenantId.ToString())
        {
            ActorId = command.OperatorId,
            TenantId = command.TenantId,
            OccurredAt = now,
            Severity = AuditSeverity.Warning,
        }, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

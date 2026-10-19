using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Enterprise.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Enterprise.Application.Features.Sso;

public sealed record SsoPolicyDto(string? Provider, bool SsoOnly, DateTimeOffset? UpdatedAt);

public sealed record GetSsoPolicyQuery(EnterpriseCaller Caller);

public sealed class GetSsoPolicyHandler(ISsoPolicyRepository policies) : IQueryHandler<GetSsoPolicyQuery, SsoPolicyDto>
{
    public async Task<Result<SsoPolicyDto>> HandleAsync(GetSsoPolicyQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var policy = await policies.FindAsync(query.Caller.TenantId, cancellationToken).ConfigureAwait(false);
        return new SsoPolicyDto(policy?.Provider, policy?.SsoOnly ?? false, policy?.UpdatedAt);
    }
}

/// <summary>
/// Sets which provider the tenant's members sign in with, and whether it is the only way in. The provider must be one the
/// token server knows (<paramref name="KnownProviders"/>); SSO-only needs a verified domain, since it is enforced per domain.
/// </summary>
public sealed record SetSsoPolicyCommand(EnterpriseCaller Caller, string? Provider, bool SsoOnly, IReadOnlyCollection<string> KnownProviders);

public sealed class SetSsoPolicyHandler(
    ISsoPolicyRepository policies,
    ITenantDomainRepository domains,
    IEnterpriseUnitOfWork unitOfWork,
    IAuditSink audit,
    TimeProvider time) : ICommandHandler<SetSsoPolicyCommand, SsoPolicyDto>
{
    public async Task<Result<SsoPolicyDto>> HandleAsync(SetSsoPolicyCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var now = time.GetUtcNow();

        // Stored as the provider spells its name: a tenant provider answers only to its canonical name.
        var canonical = command.Provider is { } provider ? command.KnownProviders.FirstOrDefault(known => string.Equals(known, provider, StringComparison.OrdinalIgnoreCase)) : null;
        if (command.Provider is { } unknown && canonical is null)
        {
            return Error.Failure(EnterpriseErrors.UnknownProvider, $"Unknown provider '{unknown}'.");
        }

        if (command.SsoOnly && command.Provider is null)
        {
            return Error.Failure(EnterpriseErrors.UnknownProvider, "SSO-only needs a provider.");
        }

        if (command.SsoOnly && !(await domains.ListForTenantAsync(command.Caller.TenantId, cancellationToken).ConfigureAwait(false)).Any(domain => domain.Status == DomainStatus.Verified))
        {
            return Error.Failure(EnterpriseErrors.NoVerifiedDomain, "Verify at least one domain first: SSO-only applies to verified domains.");
        }

        var policy = await policies.FindAsync(command.Caller.TenantId, cancellationToken).ConfigureAwait(false);
        if (policy is null)
        {
            policy = SsoPolicy.For(command.Caller.TenantId);
            policies.Add(policy);
        }

        policy.Set(canonical, command.SsoOnly, command.Caller.UserId, now);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("sso_policy.changed", "tenant", command.Caller.TenantId.ToString())
        {
            ActorId = command.Caller.UserId,
            TenantId = command.Caller.TenantId,
            OccurredAt = now,
            Severity = AuditSeverity.Warning,
            Details = new Dictionary<string, string?> { ["provider"] = policy.Provider, ["ssoOnly"] = policy.SsoOnly ? "true" : "false" },
        }, cancellationToken).ConfigureAwait(false);
        return new SsoPolicyDto(policy.Provider, policy.SsoOnly, policy.UpdatedAt);
    }
}

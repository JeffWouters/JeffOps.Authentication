using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Enterprise.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Enterprise.Application.Features.Domains;

/// <summary>A claimed domain, with the TXT record (<c>RecordName</c>, <c>RecordValue</c>) to publish for verification.</summary>
public sealed record TenantDomainDto(Guid Id, string Domain, string Status, string RecordName, string RecordValue, DateTimeOffset CreatedAt, DateTimeOffset? VerifiedAt);

internal static class DomainMapping
{
    public static TenantDomainDto ToDto(this TenantDomain domain, IOptions<EnterpriseOptions> options) =>
        new(domain.Id, domain.Domain, domain.Status.ToString(), options.ChallengeName(domain), domain.ExpectedValue(options.Value.ChallengeValuePrefix), domain.CreatedAt, domain.VerifiedAt);
}

/// <summary>Claims a domain for the caller's tenant; answers the TXT record to publish.</summary>
public sealed record ClaimDomainCommand(EnterpriseCaller Caller, string Domain);

public sealed class ClaimDomainHandler(ITenantDomainRepository domains, IEnterpriseUnitOfWork unitOfWork, IAuditSink audit, IOptions<EnterpriseOptions> options, TimeProvider time)
    : ICommandHandler<ClaimDomainCommand, TenantDomainDto>
{
    public async Task<Result<TenantDomainDto>> HandleAsync(ClaimDomainCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (TenantDomain.Normalize(command.Domain) is not { } normalized)
        {
            return Error.Failure(EnterpriseErrors.InvalidDomain, "That is not a valid domain name.");
        }

        var mine = await domains.ListForTenantAsync(command.Caller.TenantId, cancellationToken).ConfigureAwait(false);
        if (mine.FirstOrDefault(domain => domain.Domain == normalized) is { } existing)
        {
            return existing.ToDto(options);
        }

        if (mine.Count >= options.Value.MaxDomainsPerTenant)
        {
            return Error.Failure(EnterpriseErrors.TooManyDomains, $"A tenant can claim at most {options.Value.MaxDomainsPerTenant} domains.");
        }

        if (await domains.FindVerifiedAsync(normalized, cancellationToken).ConfigureAwait(false) is not null)
        {
            return Error.Conflict(EnterpriseErrors.DomainTaken, "Another organization has verified this domain.");
        }

        var claimed = TenantDomain.Claim(command.Caller.TenantId, normalized, time.GetUtcNow());
        domains.Add(claimed);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("tenant_domain.claimed", "tenant_domain", claimed.Id.ToString())
        {
            ActorId = command.Caller.UserId,
            TenantId = claimed.TenantId,
            OccurredAt = claimed.CreatedAt,
            Details = new Dictionary<string, string?> { ["domain"] = claimed.Domain },
        }, cancellationToken).ConfigureAwait(false);
        return claimed.ToDto(options);
    }
}

/// <summary>Looks the verification record up in DNS and verifies the domain when it is there.</summary>
public sealed record VerifyDomainCommand(EnterpriseCaller Caller, Guid DomainId);

public sealed class VerifyDomainHandler(
    ITenantDomainRepository domains,
    IDnsTxtResolver dns,
    IEnterpriseUnitOfWork unitOfWork,
    IAuditSink audit,
    IOptions<EnterpriseOptions> options,
    TimeProvider time) : ICommandHandler<VerifyDomainCommand, TenantDomainDto>
{
    public async Task<Result<TenantDomainDto>> HandleAsync(VerifyDomainCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var now = time.GetUtcNow();

        var domain = await domains.FindAsync(command.DomainId, cancellationToken).ConfigureAwait(false);
        if (domain is null || domain.TenantId != command.Caller.TenantId)
        {
            return Error.NotFound(EnterpriseErrors.NotFound, "No such domain.");
        }

        if (domain.Status == DomainStatus.Verified)
        {
            return domain.ToDto(options);
        }

        if (await domains.FindVerifiedAsync(domain.Domain, cancellationToken).ConfigureAwait(false) is not null)
        {
            return Error.Conflict(EnterpriseErrors.DomainTaken, "Another organization has verified this domain.");
        }

        IReadOnlyList<string> records;
        try
        {
            records = await dns.ResolveTxtAsync(options.ChallengeName(domain), cancellationToken).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // DNS failures are reported, not thrown.
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
        {
            return Error.Unavailable(EnterpriseErrors.DnsUnavailable, "DNS could not be reached. Try again shortly.");
        }

        var verified = domain.CheckTxtRecords(records, options.Value.ChallengeValuePrefix, now);
        if (!await unitOfWork.TrySaveUniqueAsync(cancellationToken).ConfigureAwait(false))
        {
            return Error.Conflict(EnterpriseErrors.DomainTaken, "Another organization has verified this domain.");
        }

        if (!verified)
        {
            return Error.Failure(EnterpriseErrors.NotVerified, $"The TXT record {options.ChallengeName(domain)} doesn't contain the expected value yet. DNS changes can take a while.");
        }

        await audit.WriteAsync(new AuditRecord("tenant_domain.verified", "tenant_domain", domain.Id.ToString())
        {
            ActorId = command.Caller.UserId,
            TenantId = domain.TenantId,
            OccurredAt = now,
            Severity = AuditSeverity.Warning,
            Details = new Dictionary<string, string?> { ["domain"] = domain.Domain },
        }, cancellationToken).ConfigureAwait(false);
        return domain.ToDto(options);
    }
}

public sealed record ListDomainsQuery(EnterpriseCaller Caller);

public sealed class ListDomainsHandler(ITenantDomainRepository domains, IOptions<EnterpriseOptions> options) : IQueryHandler<ListDomainsQuery, IReadOnlyList<TenantDomainDto>>
{
    public async Task<Result<IReadOnlyList<TenantDomainDto>>> HandleAsync(ListDomainsQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        return Result.Success<IReadOnlyList<TenantDomainDto>>(
            [.. (await domains.ListForTenantAsync(query.Caller.TenantId, cancellationToken).ConfigureAwait(false)).Select(domain => domain.ToDto(options))]);
    }
}

public sealed record RemoveDomainCommand(EnterpriseCaller Caller, Guid DomainId);

public sealed class RemoveDomainHandler(ITenantDomainRepository domains, IEnterpriseUnitOfWork unitOfWork, IAuditSink audit, TimeProvider time) : ICommandHandler<RemoveDomainCommand>
{
    public async Task<Result> HandleAsync(RemoveDomainCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var domain = await domains.FindAsync(command.DomainId, cancellationToken).ConfigureAwait(false);
        if (domain is null || domain.TenantId != command.Caller.TenantId)
        {
            return Error.NotFound(EnterpriseErrors.NotFound, "No such domain.");
        }

        domains.Remove(domain);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("tenant_domain.removed", "tenant_domain", domain.Id.ToString())
        {
            ActorId = command.Caller.UserId,
            TenantId = domain.TenantId,
            OccurredAt = time.GetUtcNow(),
            Details = new Dictionary<string, string?> { ["domain"] = domain.Domain },
        }, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

/// <summary>A platform operator takes a verified domain away from the tenant holding it (for example after it changed hands).</summary>
public sealed record RevokeDomainCommand(Guid OperatorId, string Domain);

public sealed class RevokeDomainHandler(ITenantDomainRepository domains, IEnterpriseUnitOfWork unitOfWork, IAuditSink audit, TimeProvider time) : ICommandHandler<RevokeDomainCommand>
{
    public async Task<Result> HandleAsync(RevokeDomainCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (TenantDomain.Normalize(command.Domain) is not { } normalized
            || await domains.FindVerifiedAsync(normalized, cancellationToken).ConfigureAwait(false) is not { } domain)
        {
            return Error.NotFound(EnterpriseErrors.NotFound, "No tenant has verified that domain.");
        }

        domains.Remove(domain);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("tenant_domain.revoked", "tenant_domain", domain.Id.ToString())
        {
            ActorId = command.OperatorId,
            TenantId = domain.TenantId,
            OccurredAt = time.GetUtcNow(),
            Severity = AuditSeverity.Warning,
            Details = new Dictionary<string, string?> { ["domain"] = domain.Domain },
        }, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

/// <summary>
/// One pass of the DNS proof re-check (<see cref="EnterpriseOptions.DomainRecheckInterval"/>): verified domains not checked
/// for an interval are looked up again; one whose proof stayed missing past the grace period drops back to pending. A DNS
/// outage changes nothing. Answers how many domains stopped counting.
/// </summary>
public sealed record RecheckDomainsCommand(int BatchSize = 100);

public sealed class RecheckDomainsHandler(
    ITenantDomainRepository domains,
    IDnsTxtResolver dns,
    IEnterpriseUnitOfWork unitOfWork,
    IAuditSink audit,
    IOptions<EnterpriseOptions> options,
    TimeProvider time) : ICommandHandler<RecheckDomainsCommand, int>
{
    public async Task<Result<int>> HandleAsync(RecheckDomainsCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var settings = options.Value;
        var now = time.GetUtcNow();
        var dropped = 0;
        foreach (var domain in await domains.ListVerifiedCheckedBeforeAsync(now - settings.DomainRecheckInterval, command.BatchSize, cancellationToken).ConfigureAwait(false))
        {
            IReadOnlyList<string> records;
            try
            {
                records = await dns.ResolveTxtAsync(options.ChallengeName(domain), cancellationToken).ConfigureAwait(false);
            }
#pragma warning disable CA1031 // An outage is not a missing proof: try again at the next pass.
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
            {
                continue;
            }

            if (!domain.Recheck(records, settings.ChallengeValuePrefix, now, settings.DomainProofGracePeriod))
            {
                dropped++;
                await audit.WriteAsync(new AuditRecord("tenant_domain.unverified", "tenant_domain", domain.Id.ToString())
                {
                    TenantId = domain.TenantId,
                    OccurredAt = now,
                    Severity = AuditSeverity.Warning,
                    Details = new Dictionary<string, string?> { ["domain"] = domain.Domain, ["reason"] = "dns_proof_missing" },
                }, cancellationToken).ConfigureAwait(false);
            }
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return dropped;
    }
}

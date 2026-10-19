using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authentication.Tenancy.Domain;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Tenancy.Application.Features.Directories;

/// <summary>A linked directory: its family (<c>entra</c>) and id.</summary>
public sealed record DirectoryLinkDto(string Kind, string DirectoryId, DateTimeOffset LinkedAt);

public sealed record ListDirectoriesQuery(TenancyActor Actor, Guid TenantId);

public sealed class ListDirectoriesHandler(IDirectoryLinkRepository links) : IQueryHandler<ListDirectoriesQuery, IReadOnlyList<DirectoryLinkDto>>
{
    public async Task<Result<IReadOnlyList<DirectoryLinkDto>>> HandleAsync(ListDirectoriesQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        return Result.Success<IReadOnlyList<DirectoryLinkDto>>(
            [.. (await links.ListForTenantAsync(query.TenantId, cancellationToken).ConfigureAwait(false)).Select(link => new DirectoryLinkDto(link.Kind, link.DirectoryId, link.CreatedAt))]);
    }
}

/// <summary>
/// Links an Entra directory: its people join the tenant as members when they sign in. A tenant administrator can only link
/// a directory they signed in from themselves, so no tenant can claim another organization's people.
/// </summary>
public sealed record LinkDirectoryCommand(TenancyActor Actor, Guid TenantId, Guid EntraDirectoryId);

public sealed class LinkDirectoryHandler(
    ITenantRepository tenants,
    IDirectoryLinkRepository links,
    IAccountRepository accounts,
    ITenancyUnitOfWork unitOfWork,
    IAuditSink audit,
    IOptions<TenancyOptions> options,
    TimeProvider time) : ICommandHandler<LinkDirectoryCommand, DirectoryLinkDto>
{
    public async Task<Result<DirectoryLinkDto>> HandleAsync(LinkDirectoryCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (command.EntraDirectoryId == Guid.Empty)
        {
            return Error.Failure("invalid_directory", "That is not an Entra directory id.");
        }

        if (await tenants.FindAsync(command.TenantId, cancellationToken).ConfigureAwait(false) is not { Status: not TenantStatus.Deleted })
        {
            return Error.NotFound(TenancyErrors.NotFound, "No such tenant.");
        }

        if (!command.Actor.IsOperator
            && (await accounts.FindAsync(command.Actor.AccountId, cancellationToken).ConfigureAwait(false) is not { } self
                || !TenancyMapping.EntraDirectoriesOf(self).Contains(command.EntraDirectoryId)))
        {
            return Error.Forbidden(TenancyErrors.DirectoryNotYours, "Sign in with an account from that directory first; you can only link a directory you belong to.");
        }

        var directoryId = DirectoryLink.NormalizeEntra(command.EntraDirectoryId);
        if (await links.FindAsync(DirectoryLink.EntraKind, directoryId, cancellationToken).ConfigureAwait(false) is { } existing)
        {
            return existing.TenantId == command.TenantId
                ? new DirectoryLinkDto(existing.Kind, existing.DirectoryId, existing.CreatedAt)
                : Error.Conflict(TenancyErrors.DirectoryTaken, "That directory is linked to another tenant.");
        }

        if ((await links.ListForTenantAsync(command.TenantId, cancellationToken).ConfigureAwait(false)).Count >= options.Value.MaxDirectoriesPerTenant)
        {
            return Error.Failure(TenancyErrors.TooManyDirectories, $"A tenant can link at most {options.Value.MaxDirectoriesPerTenant} directories.");
        }

        var now = time.GetUtcNow();
        var link = DirectoryLink.Entra(command.TenantId, command.EntraDirectoryId, command.Actor.AccountId, now);
        links.Add(link);
        if (!await unitOfWork.TrySaveUniqueAsync(cancellationToken).ConfigureAwait(false))
        {
            return Error.Conflict(TenancyErrors.DirectoryTaken, "That directory is linked to another tenant.");
        }

        await audit.WriteAsync(new AuditRecord("tenant.directory_linked", "tenant_directory", $"{link.Kind}/{link.DirectoryId}")
        {
            ActorId = command.Actor.AccountId,
            TenantId = command.TenantId,
            OccurredAt = now,
            Severity = AuditSeverity.Warning,
            Details = new Dictionary<string, string?> { ["kind"] = link.Kind, ["directory"] = link.DirectoryId, ["by_operator"] = command.Actor.IsOperator ? "true" : "false" },
        }, cancellationToken).ConfigureAwait(false);
        return new DirectoryLinkDto(link.Kind, link.DirectoryId, link.CreatedAt);
    }
}

/// <summary>Unlinks a directory. Members who joined through it stay members; remove them separately if they should go.</summary>
public sealed record UnlinkDirectoryCommand(TenancyActor Actor, Guid TenantId, Guid EntraDirectoryId);

public sealed class UnlinkDirectoryHandler(IDirectoryLinkRepository links, ITenancyUnitOfWork unitOfWork, IAuditSink audit, TimeProvider time)
    : ICommandHandler<UnlinkDirectoryCommand>
{
    public async Task<Result> HandleAsync(UnlinkDirectoryCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var directoryId = DirectoryLink.NormalizeEntra(command.EntraDirectoryId);
        if (await links.FindAsync(DirectoryLink.EntraKind, directoryId, cancellationToken).ConfigureAwait(false) is not { } link || link.TenantId != command.TenantId)
        {
            return Error.NotFound("directory_not_found", "That directory isn't linked to this tenant.");
        }

        links.Remove(link);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(new AuditRecord("tenant.directory_unlinked", "tenant_directory", $"{link.Kind}/{link.DirectoryId}")
        {
            ActorId = command.Actor.AccountId,
            TenantId = command.TenantId,
            OccurredAt = time.GetUtcNow(),
            Severity = AuditSeverity.Warning,
        }, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Application.Management;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Management;
using JeffOps.Authorization.Domain.Permissions;
using Microsoft.Extensions.Options;

namespace JeffOps.Authorization.Application.Features.Permissions;

/// <summary>
/// A service declares its permissions (self-registration). A service may only register codes in its own domain(s), so it
/// can't plant a definition that would make a typo in another service's permission look legitimate.
/// </summary>
public sealed record RegisterPermissionsCommand(ManagementCaller Caller, RegisterPermissionsRequest Request);

public sealed class RegisterPermissionsHandler(
    IRegisteredPermissionRepository registered,
    IUnitOfWork unitOfWork,
    IOptions<ManagementOptions> options,
    TimeProvider time) : ICommandHandler<RegisterPermissionsCommand, int>
{
    public async Task<Result<int>> HandleAsync(RegisterPermissionsCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var (caller, request) = command;

        if (!caller.IsService || caller.ServiceName is null || !string.Equals(caller.ServiceName, request.Source, StringComparison.Ordinal))
        {
            return Error.Forbidden(ManagementErrors.MissingPermission, "Only a service can register permissions, under its own name.");
        }

        if (!Permission.GrantsAny(caller.ServicePermissions, options.Value.Permissions.Register))
        {
            return Error.Forbidden(ManagementErrors.MissingPermission, $"Registering permissions needs {options.Value.Permissions.Register}.");
        }

        var domains = options.Value.RegistrationDomains.TryGetValue(caller.ServiceName, out var configured) && configured.Count > 0
            ? configured
            : [caller.ServiceName.StartsWith("svc-", StringComparison.Ordinal) ? caller.ServiceName[4..] : caller.ServiceName];

        var foreign = request.Definitions
            .Select(definition => Permission.Normalize(definition.Code))
            .Where(code => !domains.Any(domain => code.StartsWith(domain.ToLowerInvariant() + ".", StringComparison.Ordinal)))
            .ToList();
        if (foreign.Count > 0)
        {
            return Error.Forbidden(ManagementErrors.RegistrationDomain, $"{caller.ServiceName} may only register permissions in {string.Join(", ", domains)}: {string.Join(", ", foreign.Take(5))}.");
        }

        var now = time.GetUtcNow();
        var existing = (await registered.ListAsync(cancellationToken).ConfigureAwait(false)).ToDictionary(permission => permission.Code, StringComparer.Ordinal);
        var declared = new HashSet<string>(StringComparer.Ordinal);

        foreach (var definition in request.Definitions)
        {
            var code = Permission.Normalize(definition.Code);
            declared.Add(code);
            if (existing.TryGetValue(code, out var known))
            {
                known.Refresh(definition.DisplayName, definition.Domain, request.Source, now);
            }
            else
            {
                registered.Add(RegisteredPermission.Create(code, definition.DisplayName, definition.Domain, request.Source, now));
            }
        }

        // Codes this source declared before but not now: stale, kept for display.
        foreach (var stale in existing.Values.Where(permission => permission.Source == request.Source && !declared.Contains(permission.Code)))
        {
            stale.MarkStale();
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return declared.Count;
    }
}

public sealed record GetCatalogQuery;

public sealed class GetCatalogHandler(PermissionCatalog catalog) : IQueryHandler<GetCatalogQuery, IReadOnlyList<CatalogEntryDto>>
{
    public async Task<Result<IReadOnlyList<CatalogEntryDto>>> HandleAsync(GetCatalogQuery query, CancellationToken cancellationToken) =>
        Result.Success(await catalog.EntriesAsync(cancellationToken).ConfigureAwait(false));
}

using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Permissions;
using Microsoft.Extensions.Options;

namespace JeffOps.Authorization.Application.Management;

/// <summary>
/// The permission catalog: the management permissions, the host's static definitions, and what services registered. Used as a typo guard when
/// permissions are granted (docs/DESIGN.md §11.1); enforcement never depends on it.
/// </summary>
public sealed class PermissionCatalog(IPermissionCatalogProvider staticCatalog, IRegisteredPermissionRepository registered, IOptions<ManagementOptions> options)
{
    public async Task<IReadOnlyList<CatalogEntryDto>> EntriesAsync(CancellationToken cancellationToken)
    {
        var entries = staticCatalog.Definitions.Select(definition => definition.ToEntry("host")).ToDictionary(entry => entry.Code, StringComparer.OrdinalIgnoreCase);
        var management = options.Value.Permissions;
        foreach (var code in new[] { management.RolesRead, management.RolesWrite, management.AssignmentsRead, management.AssignmentsWrite, management.PoliciesWrite, management.ScopesWrite, management.Register, management.ReadApi })
        {
            var normalized = Permission.Normalize(code);
            entries.TryAdd(normalized, new CatalogEntryDto(normalized, normalized, normalized.Split('.')[0], "management", Stale: false));
        }

        foreach (var permission in await registered.ListAsync(cancellationToken).ConfigureAwait(false))
        {
            // Static definitions win on a clash.
            entries.TryAdd(permission.Code, new CatalogEntryDto(permission.Code, permission.DisplayName, permission.Domain, permission.Source, permission.Stale));
        }

        return [.. entries.Values.OrderBy(entry => entry.Code, StringComparer.Ordinal)];
    }

    /// <summary>
    /// Codes that match nothing in the catalog. Wildcards (<c>*</c>, <c>billing.*</c>) are accepted when they cover at least
    /// one known permission.
    /// </summary>
    public async Task<IReadOnlyList<string>> UnknownAsync(IReadOnlyCollection<string> codes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(codes);
        if (codes.Count == 0)
        {
            return [];
        }

        var known = (await EntriesAsync(cancellationToken).ConfigureAwait(false)).Select(entry => entry.Code).ToList();
        return [.. codes.Where(code => !known.Any(knownCode => Permission.Grants(code, knownCode)))];
    }
}

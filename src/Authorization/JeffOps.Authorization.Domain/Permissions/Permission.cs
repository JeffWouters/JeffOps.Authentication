namespace JeffOps.Authorization.Domain.Permissions;

/// <summary>
/// A permission a service declares. Codes follow <c>domain.resource.action</c> (docs/DESIGN.md §11.1).
/// </summary>
public sealed record PermissionDefinition(string Code, string DisplayName, string Domain);

/// <summary>
/// The permission-code convention and how a held permission grants a requested one.
/// </summary>
public static class Permission
{
    /// <summary>The global wildcard, held by super-admin roles.</summary>
    public const string Wildcard = "*";

    /// <summary>Builds a <c>domain.resource.action</c> code.</summary>
    public static string Of(string domain, string resource, string action) => $"{domain}.{resource}.{action}";

    /// <summary>Lower-cases and trims a code; permission matching is case-insensitive.</summary>
    public static string Normalize(string code)
    {
        ArgumentNullException.ThrowIfNull(code);
        return code.Trim().ToLowerInvariant();
    }

    /// <summary>
    /// Whether <paramref name="held"/> grants <paramref name="requested"/>: the global <c>*</c>, an exact match, or a
    /// hierarchical prefix wildcard (<c>billing.*</c> grants <c>billing.subscription.read</c>). Case-insensitive.
    /// </summary>
    public static bool Grants(string held, string requested)
    {
        ArgumentNullException.ThrowIfNull(held);
        ArgumentNullException.ThrowIfNull(requested);

        if (held == Wildcard || string.Equals(held, requested, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return held.EndsWith(".*", StringComparison.Ordinal)
            && requested.StartsWith(held[..^1], StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Whether any of <paramref name="held"/> grants <paramref name="requested"/>.</summary>
    public static bool GrantsAny(IEnumerable<string> held, string requested)
    {
        ArgumentNullException.ThrowIfNull(held);
        return held.Any(permission => Grants(permission, requested));
    }
}

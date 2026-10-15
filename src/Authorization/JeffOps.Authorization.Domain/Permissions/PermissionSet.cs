namespace JeffOps.Authorization.Domain.Permissions;

/// <summary>
/// A compiled set of held permissions. Answers <see cref="Grants"/> with the same rules as
/// <see cref="Permission.Grants"/>, but in time proportional to the number of segments of the requested code rather than
/// the number of held permissions: exact codes go in a hash set, prefix wildcards are indexed by their prefix, and each
/// prefix of the request is looked up once (docs/DESIGN.md §17, I3).
/// </summary>
public sealed class PermissionSet
{
    private readonly HashSet<string> _exact;
    private readonly HashSet<string> _prefixes;
    private readonly bool _wildcard;

    private PermissionSet(HashSet<string> exact, HashSet<string> prefixes, bool wildcard)
    {
        _exact = exact;
        _prefixes = prefixes;
        _wildcard = wildcard;
    }

    public static PermissionSet Empty { get; } = new([], [], wildcard: false);

    public static PermissionSet From(IEnumerable<string> held)
    {
        ArgumentNullException.ThrowIfNull(held);

        var exact = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var prefixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var wildcard = false;

        foreach (var permission in held)
        {
            if (string.IsNullOrWhiteSpace(permission))
            {
                continue;
            }

            var code = permission.Trim();
            if (code == Permission.Wildcard)
            {
                wildcard = true;
            }
            else if (code.EndsWith(".*", StringComparison.Ordinal))
            {
                // "billing.*" is stored as "billing." so it matches every code that starts with it.
                prefixes.Add(code[..^1]);
            }
            else
            {
                exact.Add(code);
            }
        }

        return new PermissionSet(exact, prefixes, wildcard);
    }

    public bool IsEmpty => !_wildcard && _exact.Count == 0 && _prefixes.Count == 0;

    public bool Grants(string requested)
    {
        ArgumentNullException.ThrowIfNull(requested);

        if (_wildcard || _exact.Contains(requested))
        {
            return true;
        }

        if (_prefixes.Count == 0)
        {
            return false;
        }

        // Probe every "a.", "a.b.", ... prefix of the request against the wildcard index.
        for (var dot = requested.IndexOf('.', StringComparison.Ordinal); dot >= 0; dot = requested.IndexOf('.', dot + 1))
        {
            if (_prefixes.Contains(requested[..(dot + 1)]))
            {
                return true;
            }
        }

        return false;
    }
}

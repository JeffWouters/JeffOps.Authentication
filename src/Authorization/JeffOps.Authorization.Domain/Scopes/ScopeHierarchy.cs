namespace JeffOps.Authorization.Domain.Scopes;

/// <summary>Well-known scope keys.</summary>
public static class WellKnownScopes
{
    /// <summary>The single root of the hierarchy. Built in and immutable.</summary>
    public const string System = "system";

    /// <summary>The scope a permission check targets when the caller names none.</summary>
    public const string Tenant = "tenant";
}

/// <summary>
/// Containment rules over a flat <c>key → parentKey</c> map. A grant at a scope applies to that scope and everything
/// beneath it. Pure; shared by management (write validation) and resource services (runtime checks).
/// </summary>
public static class ScopeHierarchy
{
    /// <summary>The scope and its ancestors up to the root. Cycle-safe; an unknown key yields an empty list.</summary>
    public static IReadOnlyList<string> AncestorsAndSelf(string key, IReadOnlyDictionary<string, string?> parentOf)
    {
        ArgumentNullException.ThrowIfNull(parentOf);

        var chain = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        string? current = key;
        while (current is not null && seen.Add(current) && parentOf.TryGetValue(current, out var parent))
        {
            chain.Add(current);
            current = parent;
        }

        return chain;
    }

    /// <summary>
    /// Whether <paramref name="childKey"/> is contained by <paramref name="ancestorKey"/>: they are equal, or the ancestor is
    /// above the child. A grant at <paramref name="ancestorKey"/> reaches <paramref name="childKey"/>.
    /// </summary>
    public static bool IsWithin(string childKey, string ancestorKey, IReadOnlyDictionary<string, string?> parentOf) =>
        AncestorsAndSelf(childKey, parentOf).Contains(ancestorKey, StringComparer.Ordinal);

    /// <summary>Whether reparenting <paramref name="key"/> under <paramref name="candidateParentKey"/> would create a cycle.</summary>
    public static bool WouldCycle(string key, string? candidateParentKey, IReadOnlyDictionary<string, string?> parentOf) =>
        candidateParentKey is not null
        && (string.Equals(candidateParentKey, key, StringComparison.Ordinal) || IsWithin(candidateParentKey, key, parentOf));
}

/// <summary>
/// An immutable snapshot of the scope hierarchy, for repeated containment checks against the same data.
/// </summary>
public sealed class ScopeTree
{
    private readonly Dictionary<string, string?> _parentOf;

    public ScopeTree(IEnumerable<KeyValuePair<string, string?>> parentOf)
    {
        ArgumentNullException.ThrowIfNull(parentOf);
        _parentOf = new Dictionary<string, string?>(parentOf, StringComparer.Ordinal);
    }

    public static ScopeTree Empty { get; } = new([]);

    public bool Contains(string key) => _parentOf.ContainsKey(key);

    /// <inheritdoc cref="ScopeHierarchy.IsWithin"/>
    public bool IsWithin(string childKey, string ancestorKey) => ScopeHierarchy.IsWithin(childKey, ancestorKey, _parentOf);

    /// <inheritdoc cref="ScopeHierarchy.AncestorsAndSelf"/>
    public IReadOnlyList<string> AncestorsAndSelf(string key) => ScopeHierarchy.AncestorsAndSelf(key, _parentOf);
}

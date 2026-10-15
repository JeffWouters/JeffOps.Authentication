namespace JeffOps.Authentication.Architecture.Tests.Infrastructure;

/// <summary>
/// Position of a type inside the vertical-slice tree, taken from its namespace after <c>.Features.</c>.
/// <c>X.Application.Features.PersonalAccessTokens.CreatePat</c> has the path <c>PersonalAccessTokens/CreatePat</c>.
/// </summary>
internal static class SlicePath
{
    private const string Marker = ".Features.";

    /// <summary>The slice path of a namespace, or null when the namespace is not inside a Features folder.</summary>
    public static string[]? Of(string? @namespace)
    {
        if (@namespace is null)
        {
            return null;
        }

        var index = @namespace.IndexOf(Marker, StringComparison.Ordinal);
        return index < 0 ? null : @namespace[(index + Marker.Length)..].Split('.');
    }

    /// <summary>
    /// Two slice paths may depend on each other when one is a prefix of the other: a use case may use its own area's
    /// shared types, and an area-level endpoint group may use the use cases of its area, in any layer. Sibling use
    /// cases (<c>PersonalAccessTokens/CreatePat</c> and <c>PersonalAccessTokens/RevokePat</c>) and different areas may not.
    /// </summary>
    public static bool AreOnTheSameBranch(string[] from, string[] to)
    {
        var shared = Math.Min(from.Length, to.Length);
        for (var i = 0; i < shared; i++)
        {
            if (!string.Equals(from[i], to[i], StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }
}

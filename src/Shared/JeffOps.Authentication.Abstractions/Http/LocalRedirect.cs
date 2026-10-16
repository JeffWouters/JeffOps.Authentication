namespace JeffOps.Authentication.Abstractions.Http;

/// <summary>
/// Return URLs after sign-in and sign-out: only paths on this site are honoured, so a crafted link can't turn sign-in into
/// an open redirect.
/// </summary>
public static class LocalRedirect
{
    /// <summary>
    /// Whether <paramref name="url"/> is a path on this site: it starts with a single <c>/</c>, is not protocol-relative
    /// (<c>//host</c>, <c>/\host</c>) and holds no control characters (browsers drop tabs and newlines from a Location
    /// header, so <c>/%09/evil.test</c> would become <c>//evil.test</c>).
    /// </summary>
    public static bool IsLocal(string? url) =>
        !string.IsNullOrEmpty(url)
        && url[0] == '/'
        && (url.Length == 1 || (url[1] != '/' && url[1] != '\\'))
        && !url.Any(char.IsControl);

    /// <summary><paramref name="url"/> when it is local, otherwise <c>/</c>.</summary>
    public static string OrRoot(string? url) => IsLocal(url) ? url! : "/";
}

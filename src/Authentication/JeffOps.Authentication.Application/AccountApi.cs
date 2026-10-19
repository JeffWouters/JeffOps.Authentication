namespace JeffOps.Authentication.Application;

/// <summary>
/// The token server's own APIs (account, personal access tokens, credentials, delegation, enterprise, the account
/// directory). They accept only access tokens issued for <see cref="TokenServerOptions.AccountAudience"/>, which the server
/// issues for the <see cref="Scope"/> scope and only in a token with no other audience: a token meant for a resource API
/// can't be replayed here by whoever receives it.
/// </summary>
public static class AccountApi
{
    /// <summary>The scope a client requests (alone, or by narrowing a refresh) for an access token to the token server's own APIs.</summary>
    public const string Scope = "account";

    /// <summary>The authorization policy of the token server's own APIs: a valid access token whose audience is the account audience.</summary>
    public const string PolicyName = "JeffOps.AccountApi";

    /// <summary>
    /// The audiences an access token gets for <paramref name="scopes"/>: the account audience when the account scope is
    /// requested with no API scope, otherwise the API scopes' audiences (never the account audience next to them).
    /// </summary>
    public static IReadOnlyList<string> AudiencesOf(IEnumerable<string> scopes, TokenServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        ArgumentNullException.ThrowIfNull(options);
        var requested = scopes.ToList();
        var apiAudiences = requested
            .SelectMany(scope => options.ApiScopes.TryGetValue(scope, out var audiences) ? audiences : [])
            .Where(audience => !string.IsNullOrWhiteSpace(audience))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        return apiAudiences.Count == 0 && requested.Contains(Scope, StringComparer.Ordinal) ? [options.AccountAudience] : apiAudiences;
    }
}

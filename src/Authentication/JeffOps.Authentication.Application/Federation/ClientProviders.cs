namespace JeffOps.Authentication.Application.Federation;

/// <summary>
/// Which identity providers a client accepts (<see cref="ClientDefinition.Providers"/>), for the login page, home realm
/// discovery and the authorize endpoint.
/// </summary>
public static class ClientProviders
{
    /// <summary>The provider name of local accounts (passwords, passkeys, emailed codes).</summary>
    public const string Local = "local";

    private const string AuthorizePath = "/connect/authorize";

    /// <summary>The configured client <paramref name="clientId"/>, or null.</summary>
    public static ClientDefinition? Find(TokenServerOptions options, string? clientId)
    {
        ArgumentNullException.ThrowIfNull(options);
        return string.IsNullOrEmpty(clientId)
            ? null
            : options.Clients.FirstOrDefault(client => string.Equals(client.ClientId, clientId, StringComparison.Ordinal));
    }

    /// <summary>
    /// The client a sign-in is for, from its return URL: the <c>client_id</c> of an authorization request
    /// (<c>/connect/authorize?client_id=…</c>, also with pushed requests, which repeat it). Null for any other return URL.
    /// </summary>
    public static ClientDefinition? ForReturnUrl(TokenServerOptions options, string? returnUrl) =>
        Find(options, ClientIdOf(returnUrl));

    /// <summary>
    /// Whether a sign-in through <paramref name="provider"/> may be used for <paramref name="client"/>. Unknown clients and
    /// clients without a list accept every provider; a tenant's own provider is always accepted; a sign-in that doesn't say
    /// where it came from (made before sign-ins recorded it) is accepted only by clients without a list.
    /// </summary>
    public static bool Allows(ClientDefinition? client, string? provider) =>
        client is null
        || client.Providers.Count == 0
        || TenantProviderNames.IsTenantProvider(provider)
        || (provider is not null && client.Providers.Contains(provider, StringComparer.Ordinal));

    /// <summary>The <c>client_id</c> of the authorization request a return URL resumes, or null.</summary>
    public static string? ClientIdOf(string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl))
        {
            return null;
        }

        var question = returnUrl.IndexOf('?', StringComparison.Ordinal);
        if (question < 0 || !returnUrl.AsSpan(0, question).EndsWith(AuthorizePath, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        foreach (var pair in returnUrl[(question + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var equals = pair.IndexOf('=', StringComparison.Ordinal);
            if (equals > 0 && Unescape(pair[..equals]) == "client_id")
            {
                return Unescape(pair[(equals + 1)..]);
            }
        }

        return null;
    }

    private static string Unescape(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));
}

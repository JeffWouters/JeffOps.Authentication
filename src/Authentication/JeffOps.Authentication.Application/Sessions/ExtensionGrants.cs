using System.Security.Claims;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Application.Sessions;

/// <summary>
/// A token request for an extension grant type (<c>{ExtensionGrantNamespace}:{name}</c>) contributed by a module, such as
/// Delegation (docs/DESIGN.md §12).
/// </summary>
/// <param name="ClientId">The authenticated client making the request.</param>
/// <param name="Scopes">The requested scopes.</param>
/// <param name="Parameters">The request's other parameters.</param>
/// <param name="Actor">
/// The principal of the request's <c>actor_token</c> (RFC 8693 §2.1): an access token this server issued, already validated.
/// Null when the request carried none.
/// </param>
public sealed record ExtensionGrantRequest(
    string ClientId,
    IReadOnlyCollection<string> Scopes,
    IReadOnlyDictionary<string, string?> Parameters,
    ClaimsPrincipal? Actor)
{
    public string? Parameter(string name) => Parameters.GetValueOrDefault(name);
}

/// <summary>Decides an extension grant. Register with <see cref="ExtensionGrantRegistration"/>.</summary>
public interface IExtensionGrantHandler
{
    /// <summary>The grant's name; the grant type is <c>{ExtensionGrantNamespace}:{Name}</c>.</summary>
    string Name { get; }

    Task<Result<IssuedIdentity>> HandleAsync(ExtensionGrantRequest request, CancellationToken cancellationToken);
}

/// <summary>DPoP key binding (RFC 9449) between the token endpoint and token generation.</summary>
public static class DpopBinding
{
    /// <summary>
    /// The private claim carrying the bound key's thumbprint. It travels in codes and refresh tokens (so they stay bound) and
    /// becomes the access token's <c>cnf.jkt</c>; it never appears in a token as itself.
    /// </summary>
    public const string ClaimType = "jeffops_dpop_jkt";

    /// <summary>
    /// The key a validated access token is bound to: <c>(true, jkt)</c> for a DPoP binding (<c>cnf.jkt</c>),
    /// <c>(true, null)</c> for a binding this server can't check (which must be refused), <c>(false, null)</c> when unbound.
    /// </summary>
    public static (bool Bound, string? Jkt) Of(ClaimsPrincipal accessToken)
    {
        ArgumentNullException.ThrowIfNull(accessToken);
        if (accessToken.FindFirst("cnf")?.Value is not { } cnf)
        {
            return (false, null);
        }

        try
        {
            using var document = System.Text.Json.JsonDocument.Parse(cnf);
            return document.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object
                && document.RootElement.TryGetProperty("jkt", out var jkt) && jkt.ValueKind == System.Text.Json.JsonValueKind.String
                ? (true, jkt.GetString())
                : (true, null);
        }
        catch (System.Text.Json.JsonException)
        {
            return (true, null);
        }
    }
}

/// <summary>Declares an extension grant so the server accepts and advertises its grant type.</summary>
public sealed record ExtensionGrantRegistration(string Name);

/// <summary>
/// A sign-in method the hosted login page offers next to external providers, for example local passwords: the page shows its
/// form, which posts to <see cref="FormAction"/>. Registered by the module that implements it.
/// </summary>
/// <param name="Name">Stable name, for example <c>password</c>.</param>
/// <param name="FormAction">Where the page's form posts.</param>
/// <param name="Enabled">Whether the method is on in this environment.</param>
public sealed record InteractiveSignInMethod(string Name, string FormAction, bool Enabled);

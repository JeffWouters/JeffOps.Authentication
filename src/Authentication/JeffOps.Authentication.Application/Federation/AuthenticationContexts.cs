using System.Security.Claims;
using System.Text.Json;
using JeffOps.Authentication.Application.Sessions;

namespace JeffOps.Authentication.Application.Federation;

/// <summary>
/// Authentication contexts a client asks for with <c>acr_values</c> (OpenID Connect Core 3.1.2.1), such as an Entra
/// Conditional Access authentication context (<c>c1</c>). The token server asks the provider for them on the user's behalf:
/// <c>acr_values</c>, and for Entra the <c>claims</c> parameter with <c>acrs</c>, which is how Entra takes the request. A
/// client that lists the provider's <c>acrs</c> or <c>acr</c> in <see cref="ClientDefinition.UpstreamClaims"/> receives what
/// the provider answered, and judges it itself.
/// </summary>
/// <remarks>
/// A sign-in whose provider already reported every requested context counts. Otherwise the user signs in again once, with
/// the request in the return URL (<see cref="Parameter"/>), so a provider that can't satisfy it doesn't send the user round
/// in circles: the client then gets tokens without the context. A local sign-in, or one through a tenant's provider (whose
/// claims this server doesn't keep), can't report contexts, so it isn't sent round at all. The parameter only ever asks the
/// provider for more; it grants nothing.
/// </remarks>
public static class AuthenticationContexts
{
    /// <summary>The return URL parameter with the contexts the provider is asked for.</summary>
    public const string Parameter = "jeffops_acr_values";

    /// <summary>The provider claims that report contexts: Entra's <c>acrs</c> and OpenID Connect's <c>acr</c>.</summary>
    public static readonly IReadOnlyList<string> ProviderClaims = ["acrs", "acr"];

    private const int MaxValues = 5;
    private const int MaxLength = 64;

    /// <summary>The contexts in an <c>acr_values</c> value (space-separated); empty when there are none or it isn't valid.</summary>
    public static IReadOnlyList<string> Parse(string? acrValues)
    {
        var values = (acrValues ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        return values.Count <= MaxValues && values.All(IsValid) ? values : [];
    }

    /// <summary>The contexts a local return URL asks the provider for (<see cref="Parameter"/>).</summary>
    public static IReadOnlyList<string> RequestedIn(string? returnUrl) => Parse(ReturnUrlQuery.Value(returnUrl, Parameter));

    /// <summary>Whether the sign-in's provider reported every one of <paramref name="requested"/>.</summary>
    public static bool Satisfied(ClaimsPrincipal? signIn, IReadOnlyCollection<string> requested)
    {
        ArgumentNullException.ThrowIfNull(requested);
        var reported = ProviderClaims.SelectMany(type => UpstreamIdentity.SignInValues(signIn, type))
            .SelectMany(value => value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .ToHashSet(StringComparer.Ordinal);
        return requested.All(reported.Contains);
    }

    /// <summary>
    /// Whether the user signs in again for <paramref name="requested"/>: the sign-in came through a provider whose claims this
    /// server keeps, and it didn't report all of them.
    /// </summary>
    public static bool Missing(ClaimsPrincipal? signIn, IReadOnlyCollection<string> requested)
    {
        ArgumentNullException.ThrowIfNull(requested);
        return requested.Count > 0 && UpstreamIdentity.Forwards(SignInPrincipal.ProviderOf(signIn)) && !Satisfied(signIn, requested);
    }

    /// <summary>Entra's form of the request: the <c>claims</c> parameter asking for <c>acrs</c> in the ID token.</summary>
    public static string EntraClaimsParameter(IReadOnlyList<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        object acrs = values.Count == 1
            ? new Dictionary<string, object> { ["essential"] = true, ["value"] = values[0] }
            : new Dictionary<string, object> { ["essential"] = true, ["values"] = values };
        return JsonSerializer.Serialize(new Dictionary<string, object> { ["id_token"] = new Dictionary<string, object> { ["acrs"] = acrs } });
    }

    private static bool IsValid(string value) =>
        value.Length <= MaxLength && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_' or ':' or '/');
}

/// <summary>Reads one parameter of a local return URL's query (as the token server builds them).</summary>
internal static class ReturnUrlQuery
{
    public static string? Value(string? returnUrl, string name)
    {
        var start = returnUrl?.IndexOf('?', StringComparison.Ordinal) ?? -1;
        if (returnUrl is null || start < 0)
        {
            return null;
        }

        var query = returnUrl[(start + 1)..];
        if (query.IndexOf('#', StringComparison.Ordinal) is var fragment and >= 0)
        {
            query = query[..fragment];
        }

        foreach (var pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = pair.IndexOf('=', StringComparison.Ordinal);
            if (separator > 0 && string.Equals(Uri.UnescapeDataString(pair[..separator]), name, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[(separator + 1)..].Replace('+', ' '));
            }
        }

        return null;
    }
}

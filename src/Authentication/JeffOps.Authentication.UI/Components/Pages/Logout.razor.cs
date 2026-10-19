using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authentication.UI.Components.Pages;

/// <summary>
/// Confirms a sign-out an application asked for without proving it knows the session (no matching <c>id_token_hint</c>), so
/// another site can't sign the user out with a link. Posts the end-session request back with the user's confirmation.
/// </summary>
public sealed partial class Logout
{
    /// <summary>The current request, cascaded during static server rendering.</summary>
    [CascadingParameter]
    public HttpContext? HttpContext { get; set; }

    /// <summary>The end-session request's parameters, passed on unchanged.</summary>
    private IReadOnlyList<(string Name, string Value)> Parameters { get; set; } = [];

    /// <inheritdoc />
    protected override void OnInitialized()
    {
        Login.ApplySecurityHeaders(HttpContext);
        Parameters = HttpContext is null
            ? []
            : [.. HttpContext.Request.Query
                .Where(pair => pair.Key is not ("confirm" or "__RequestVerificationToken"))
                .SelectMany(pair => pair.Value.Select(value => (pair.Key, value ?? string.Empty)))];
    }
}

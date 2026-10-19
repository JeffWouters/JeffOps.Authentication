using JeffOps.Authentication.Bff.Middleware;
using JeffOps.Authentication.Bff.Sessions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Bff.Endpoints;

/// <summary>
/// <c>/bff/account/{path}</c>: forwards to the token server's own APIs with the own session's account token
/// (<see cref="BffOptions.AccountApi"/>). Only paths under <see cref="BffOptions.AccountApiPaths"/> are reachable, only from an
/// own session (an acting session never manages the account it acts as), and the CSRF header applies like any /bff request.
/// </summary>
internal static class AccountApiEndpoints
{
    private static readonly string[] Methods = [HttpMethods.Get, HttpMethods.Post, HttpMethods.Put, HttpMethods.Patch, HttpMethods.Delete];

    public static void Map(IEndpointRouteBuilder endpoints) =>
        endpoints.MapMethods(BffPaths.Account, Methods, ForwardAsync).ExcludeFromDescription().AllowAnonymous().DisableAntiforgery();

    private static async Task ForwardAsync(string path, HttpContext context, BffSessionManager sessions, IHttpClientFactory http, IOptions<BffOptions> options)
    {
        var settings = options.Value;
        if (Target(settings, path, context.Request.QueryString) is not { } target)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        if (!context.Request.Cookies.TryGetValue(BffCookie.Name(context.Request, settings), out var id) || string.IsNullOrEmpty(id)
            || await sessions.GetAccountTokenAsync(id, context.RequestAborted).ConfigureAwait(false) is not { } token)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        using var request = new HttpRequestMessage(new HttpMethod(context.Request.Method), target);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        if (context.Request.ContentLength > 0 || context.Request.Headers.TransferEncoding.Count > 0)
        {
            request.Content = new StreamContent(context.Request.Body);
            if (context.Request.ContentType is { } contentType)
            {
                request.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
            }
        }

        foreach (var header in new[] { "Accept", "If-Match", "If-None-Match" })
        {
            if (context.Request.Headers.TryGetValue(header, out var values))
            {
                request.Headers.TryAddWithoutValidation(header, (IEnumerable<string?>)values);
            }
        }

        using var client = http.CreateClient(ActingEndpoints.AuthorityClient);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted).ConfigureAwait(false);
        context.Response.StatusCode = (int)response.StatusCode;
        if (response.Content.Headers.ContentType is { } type)
        {
            context.Response.ContentType = type.ToString();
        }

        if (response.Headers.ETag is { } etag)
        {
            context.Response.Headers.ETag = etag.ToString();
        }

        await response.Content.CopyToAsync(context.Response.Body, context.RequestAborted).ConfigureAwait(false);
    }

    /// <summary>
    /// The token server URL for <paramref name="path"/>, or null when it isn't under an allowed prefix of the authority (no
    /// dot segments, backslashes, encoded characters or schemes can move it elsewhere).
    /// </summary>
    internal static Uri? Target(BffOptions settings, string? path, QueryString query)
    {
        if (settings.Authority is not { } authority || !settings.UsesAccountApi || string.IsNullOrEmpty(path)
            || path.Contains("..", StringComparison.Ordinal) || path.Contains('\\', StringComparison.Ordinal)
            || path.Contains('%', StringComparison.Ordinal) || path.Contains(':', StringComparison.Ordinal)
            || path.StartsWith('/') || path.Any(char.IsControl)
            || !settings.AccountApiPaths.Any(prefix => path.StartsWith(prefix, StringComparison.Ordinal)))
        {
            return null;
        }

        var root = authority.AbsoluteUri.EndsWith('/') ? authority : new Uri(authority.AbsoluteUri + "/");
        var target = new Uri(root, path + query.ToUriComponent());
        return string.Equals(target.GetLeftPart(UriPartial.Authority), root.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase)
            && settings.AccountApiPaths.Any(prefix => target.AbsolutePath.StartsWith(root.AbsolutePath + prefix, StringComparison.Ordinal))
            ? target
            : null;
    }
}

using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using JeffOps.Authentication.Abstractions.RateLimiting;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Server;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// Rate limits of the protocol endpoints (docs/DESIGN.md D28, <see cref="RateLimitOptions"/>): per client address and per
/// client, checked first, before a client secret is hashed or anything is read from the database. Discovery and the key
/// set aren't limited (they are cacheable and cheap). A refused request gets 429 with <c>Retry-After</c>.
/// </summary>
internal static class ProtocolRateLimits
{
    public static void Register(OpenIddictServerBuilder server) =>
        server.AddEventHandler<OpenIddictServerEvents.ProcessRequestContext>(handler => handler
            .UseInlineHandler(async context =>
            {
                if (context.EndpointType is OpenIddictServerEndpointType.Unknown or OpenIddictServerEndpointType.Configuration or OpenIddictServerEndpointType.JsonWebKeySet
                    || context.Transaction.GetHttpRequest() is not { } http)
                {
                    return;
                }

                var services = http.HttpContext.RequestServices;
                var options = services.GetRequiredService<IOptions<RateLimitOptions>>().Value;
                if (!options.Enabled)
                {
                    return;
                }

                var limiter = services.GetRequiredService<RequestRateLimiter>();
                var clientId = await ClientIdOfAsync(http).ConfigureAwait(false);
                if (limiter.TryAcquire(options.ProtocolPerAddress, RateLimitPartitions.For("protocol-address", http.HttpContext.Connection.RemoteIpAddress?.ToString()), out var wait)
                    && (clientId is null || limiter.TryAcquire(options.ProtocolPerClient, RateLimitPartitions.For("protocol-client", clientId), out wait)))
                {
                    return;
                }

                var response = http.HttpContext.Response;
                response.StatusCode = StatusCodes.Status429TooManyRequests;
                response.Headers.RetryAfter = Math.Max(1, (int)Math.Ceiling(wait.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
                response.Headers.CacheControl = "no-store";
                await response.WriteAsJsonAsync(
                    new Dictionary<string, string> { ["error"] = "temporarily_unavailable", ["error_description"] = "Too many requests. Try again later." },
                    http.HttpContext.RequestAborted).ConfigureAwait(false);
                context.HandleRequest();
            })
            // Once the endpoint is known, before anything reads the request.
            .SetOrder(OpenIddictServerHandlers.InferEndpointType.Descriptor.Order + 500)
            .SetType(OpenIddictServerHandlerType.Custom));

    /// <summary>The client the request names: HTTP Basic credentials, or <c>client_id</c> in the form or query.</summary>
    private static async ValueTask<string?> ClientIdOfAsync(HttpRequest http)
    {
        if (AuthenticationHeaderValue.TryParse(http.Headers.Authorization, out var header)
            && string.Equals(header.Scheme, "Basic", StringComparison.OrdinalIgnoreCase) && header.Parameter is { Length: > 0 and < 1024 } basic)
        {
            try
            {
                var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(basic));
                var separator = credentials.IndexOf(':', StringComparison.Ordinal);
                if (separator > 0)
                {
                    return Uri.UnescapeDataString(credentials[..separator]);
                }
            }
            catch (FormatException)
            {
                return null;
            }
        }

        var clientId = http.HasFormContentType
            ? (await http.ReadFormAsync(http.HttpContext.RequestAborted).ConfigureAwait(false))["client_id"].ToString()
            : http.Query["client_id"].ToString();
        return string.IsNullOrEmpty(clientId) ? null : clientId;
    }
}

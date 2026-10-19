using System.Globalization;
using JeffOps.Authentication.Abstractions.Replay;
using Microsoft.AspNetCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// A client assertion (<c>private_key_jwt</c>, RFC 7523 §3) authenticates one request: its <c>jti</c> is recorded in the
/// shared replay cache until it expires, and an assertion without one, or seen before, is refused. OpenIddict validates the
/// signature, issuer, audience and lifetime; this adds the one-time use.
/// </summary>
internal static class ClientAssertionReplay
{
    public static void Register(OpenIddictServerBuilder server) =>
        server.AddEventHandler<OpenIddictServerEvents.ProcessAuthenticationContext>(handler => handler
            .UseInlineHandler(async context =>
            {
                if (context.ClientAssertionPrincipal is not { } assertion || context.Transaction.GetHttpRequest() is not { } http)
                {
                    return;
                }

                var jti = assertion.GetClaim(Claims.JwtId);
                var expires = long.TryParse(assertion.GetClaim(Claims.ExpiresAt), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
                    ? DateTimeOffset.FromUnixTimeSeconds(seconds)
                    : assertion.GetExpirationDate();
                if (string.IsNullOrEmpty(jti) || expires is null)
                {
                    context.Reject(Errors.InvalidClient, "The client assertion needs a jti and an exp.");
                    return;
                }

                var key = ReplayKeys.For("client-assertion", context.ClientId + "\n" + jti);
                if (!await http.HttpContext.RequestServices.GetRequiredService<IReplayCache>()
                        .TryAddAsync(key, expires.Value + ClockSkew, http.HttpContext.RequestAborted).ConfigureAwait(false))
                {
                    context.Reject(Errors.InvalidClient, "The client assertion was already used.");
                }
            })
            .SetOrder(OpenIddictServerHandlers.ValidateClientAssertion.Descriptor.Order + 1_000)
            .SetType(OpenIddictServerHandlerType.Custom));

    /// <summary>A margin past the assertion's expiry for clock differences between instances.</summary>
    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(1);
}

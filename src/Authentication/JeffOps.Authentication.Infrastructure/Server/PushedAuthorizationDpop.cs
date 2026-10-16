using JeffOps.Authentication.Abstractions.Dpop;
using JeffOps.Authentication.Abstractions.Replay;
using Microsoft.AspNetCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Server;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// DPoP at the pushed authorization request endpoint (RFC 9449 §10.1): a proof sent with the pushed request binds the
/// authorization code to its key, exactly as <c>dpop_jkt</c> does, so only a proof of that key redeems the code. A
/// <c>dpop_jkt</c> that names another key than the proof is refused.
/// </summary>
internal static class PushedAuthorizationDpop
{
    private const string InvalidProof = "invalid_dpop_proof";
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    public static void Register(OpenIddictServerBuilder server) =>
        server.AddEventHandler<OpenIddictServerEvents.ValidatePushedAuthorizationRequestContext>(handler => handler
            .UseInlineHandler(async context =>
            {
                if (context.Transaction.GetHttpRequest() is not { } http)
                {
                    return;
                }

                var proofs = http.Headers[DpopProofValidator.HeaderName];
                if (proofs.Count == 0)
                {
                    return;
                }

                if (proofs.Count > 1)
                {
                    context.Reject(InvalidProof, "Send exactly one DPoP proof.");
                    return;
                }

                var services = http.HttpContext.RequestServices;
                var now = services.GetRequiredService<TimeProvider>().GetUtcNow();
                var target = new Uri($"{http.Scheme}://{http.Host}{http.PathBase}{http.Path}");
                var (proof, error) = DpopProofValidator.Validate(proofs[0], "POST", target, now, Window);
                if (proof is null)
                {
                    context.Reject(InvalidProof, error);
                    return;
                }

                if ((string?)context.Request["dpop_jkt"] is { Length: > 0 } requested && !string.Equals(requested, proof.Jkt, StringComparison.Ordinal))
                {
                    context.Reject(InvalidProof, "dpop_jkt names another key than the DPoP proof.");
                    return;
                }

                if (!await services.GetRequiredService<IReplayCache>()
                        .TryAddAsync(ReplayKeys.For("dpop", proof.Jkt + "\n" + proof.Jti), now + Window + Window, http.HttpContext.RequestAborted)
                        .ConfigureAwait(false))
                {
                    context.Reject(InvalidProof, "This DPoP proof was already used.");
                    return;
                }

                // Stored with the pushed request; the authorize endpoint binds the code to it.
                context.Request["dpop_jkt"] = proof.Jkt;
            })
            .SetOrder(int.MaxValue - 100_000)
            .SetType(OpenIddictServerHandlerType.Custom));
}

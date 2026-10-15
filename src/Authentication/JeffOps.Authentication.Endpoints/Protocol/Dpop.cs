using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Dpop;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace JeffOps.Authentication.Endpoints.Protocol;

/// <summary>
/// DPoP at the token endpoint (RFC 9449): a request with a <c>DPoP</c> header gets an access token bound to the proof's key
/// (<c>cnf.jkt</c>) and a refresh token bound to it too; clients configured with <c>RequireDpop</c> must send one.
/// </summary>
internal static class Dpop
{
    public const string InvalidProof = "invalid_dpop_proof";

    /// <summary>The private claim that binds codes and refresh tokens to the DPoP key.</summary>
    public const string BindingClaim = DpopBinding.ClaimType;

    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    /// <summary>The proof's key thumbprint, null without a proof (when allowed), or why the request is refused.</summary>
    public static Result<string?> Check(HttpContext context, OpenIddictRequest request, TokenServerOptions options, TimeProvider time)
    {
        var headers = context.Request.Headers[DpopProofValidator.HeaderName];
        var required = options.Clients.Any(client => client.RequireDpop && string.Equals(client.ClientId, request.ClientId, StringComparison.Ordinal));
        if (headers.Count == 0)
        {
            return required
                ? Error.Unauthorized(InvalidProof, "This client must prove possession of a key with DPoP.")
                : Result.Success<string?>(null);
        }

        if (headers.Count > 1)
        {
            return Error.Unauthorized(InvalidProof, "Send exactly one DPoP proof.");
        }

        var target = new Uri($"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}{context.Request.Path}");
        var now = time.GetUtcNow();
        var (proof, error) = DpopProofValidator.Validate(headers[0], HttpMethods.Post, target, now, Window);
        if (proof is null)
        {
            return Error.Unauthorized(InvalidProof, error!);
        }

        // Each proof works once.
        var replay = context.RequestServices.GetRequiredService<IMemoryCache>();
        var key = $"jeffops:dpop:{proof.Jkt}:{proof.Jti}";
        if (replay.TryGetValue(key, out _))
        {
            return Error.Unauthorized(InvalidProof, "This DPoP proof was already used.");
        }

        replay.Set(key, true, now + Window + Window);
        return proof.Jkt;
    }

    /// <summary>Adds the key binding; token generation turns it into the access token's <c>cnf.jkt</c>.</summary>
    public static IssuedIdentity Bind(IssuedIdentity issued, string jkt) => issued with
    {
        Claims = [.. issued.Claims.Where(claim => claim.Type != BindingClaim), new Claim(BindingClaim, jkt)],
    };
}

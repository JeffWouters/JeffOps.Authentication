using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Dpop;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.AspNetCore.DataProtection;
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

    /// <summary>The error asking the client to retry with the nonce in the <c>DPoP-Nonce</c> header.</summary>
    public const string UseNonce = "use_dpop_nonce";

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

        // Server nonces: every answer carries a fresh one; a proof without a valid one is turned away with it.
        if (options.RequireDpopNonce)
        {
            var nonces = Nonces(context);
            context.Response.Headers[DpopProofValidator.NonceHeaderName] = Issue(nonces, now);
            if (!IsValid(nonces, proof.Nonce, now))
            {
                return Error.Unauthorized(UseNonce, "Retry with the nonce in the DPoP-Nonce header.");
            }
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

    /// <summary>
    /// The key a client asked the authorization code to be bound to (<c>dpop_jkt</c>, RFC 9449 §10), when it is a well-formed
    /// SHA-256 thumbprint; the code is then redeemable only with a proof of that key.
    /// </summary>
    public static string? RequestedBinding(OpenIddictRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var jkt = (string?)request["dpop_jkt"];
        return jkt is { Length: 43 } && jkt.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_') ? jkt : null;
    }

    private static IDataProtector Nonces(HttpContext context) =>
        context.RequestServices.GetRequiredService<IDataProtectionProvider>().CreateProtector("JeffOps.Dpop.Nonce");

    private static string Issue(IDataProtector nonces, DateTimeOffset now) =>
        DpopProofValidator.Base64Url(nonces.Protect(BitConverter.GetBytes(now.ToUnixTimeSeconds())));

    private static bool IsValid(IDataProtector nonces, string? nonce, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(nonce))
        {
            return false;
        }

        try
        {
            var base64 = nonce.Replace('-', '+').Replace('_', '/');
            base64 = base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '=');
            var issued = DateTimeOffset.FromUnixTimeSeconds(BitConverter.ToInt64(nonces.Unprotect(Convert.FromBase64String(base64))));
            return issued <= now + TimeSpan.FromMinutes(1) && now - issued <= Window;
        }
        catch (Exception exception) when (exception is FormatException or System.Security.Cryptography.CryptographicException or ArgumentException)
        {
            return false;
        }
    }

    /// <summary>Adds the key binding; token generation turns it into the access token's <c>cnf.jkt</c>.</summary>
    public static IssuedIdentity Bind(IssuedIdentity issued, string jkt) => issued with
    {
        Claims = [.. issued.Claims.Where(claim => claim.Type != BindingClaim), new Claim(BindingClaim, jkt)],
    };
}

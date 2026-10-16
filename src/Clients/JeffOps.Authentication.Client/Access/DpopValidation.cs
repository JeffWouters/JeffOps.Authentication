using System.Text.Json;
using JeffOps.Authentication.Abstractions.Dpop;
using JeffOps.Authentication.Abstractions.Replay;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace JeffOps.Authentication.Client.Access;

/// <summary>How a resource service treats DPoP-bound tokens (RFC 9449).</summary>
public enum DpopMode
{
    /// <summary>Bearer and DPoP tokens are accepted; a DPoP-bound token (<c>cnf.jkt</c>) always needs its proof.</summary>
    Allowed,

    /// <summary>Only DPoP-bound tokens with a valid proof are accepted.</summary>
    Required,
}

/// <summary>
/// DPoP at a resource service: reads <c>Authorization: DPoP</c>, and for a token bound to a key (<c>cnf.jkt</c>) requires a
/// fresh, unused proof for this request (<c>htm</c>, <c>htu</c>, <c>ath</c>) signed by that key — so a stolen token is useless
/// without the client's private key. A bound token presented as a plain bearer token is refused.
/// </summary>
internal static class DpopValidation
{
    private const string SchemeItem = "jeffops:dpop:scheme";
    private const string FailedItem = "jeffops:dpop:failed";
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    public static void Attach(JwtBearerOptions jwt, DpopMode mode, TimeProvider time)
    {
        // The checks live in JwtBearerOptions.Events and need the token as a JsonWebToken; configurations that bypass either
        // would let a bound token through without its proof, so they are refused.
        if (jwt.EventsType is not null)
        {
            throw new InvalidOperationException("JwtBearerOptions.EventsType is not supported with JeffOps authentication: DPoP checks run in JwtBearerOptions.Events. Set Events instead.");
        }

        if (jwt.UseSecurityTokenValidators)
        {
            throw new InvalidOperationException("JwtBearerOptions.UseSecurityTokenValidators is not supported with JeffOps authentication: DPoP checks need JsonWebTokenHandler.");
        }

        var events = jwt.Events ?? new JwtBearerEvents();
        var received = events.OnMessageReceived;
        var validated = events.OnTokenValidated;
        var challenge = events.OnChallenge;

        events.OnMessageReceived = async context =>
        {
            var header = context.Request.Headers.Authorization.ToString();
            if (header.StartsWith(DpopProofValidator.Scheme + " ", StringComparison.OrdinalIgnoreCase))
            {
                context.Token = header[(DpopProofValidator.Scheme.Length + 1)..].Trim();
                context.HttpContext.Items[SchemeItem] = true;
            }

            await received(context).ConfigureAwait(false);
        };

        events.OnTokenValidated = async context =>
        {
            if (await CheckAsync(context, mode, time).ConfigureAwait(false) is { } failure)
            {
                context.HttpContext.Items[FailedItem] = true;
                context.Fail(failure);
                return;
            }

            await validated(context).ConfigureAwait(false);
        };

        events.OnChallenge = async context =>
        {
            if (context.HttpContext.Items.ContainsKey(FailedItem) || mode == DpopMode.Required)
            {
                context.Response.Headers.WWWAuthenticate = Microsoft.Extensions.Primitives.StringValues.Concat(
                    context.Response.Headers.WWWAuthenticate,
                    $"{DpopProofValidator.Scheme} error=\"invalid_token\", algs=\"{string.Join(' ', DpopProofValidator.Algorithms)}\"");
            }

            await challenge(context).ConfigureAwait(false);
        };

        jwt.Events = events;
    }

    private static async Task<string?> CheckAsync(TokenValidatedContext context, DpopMode mode, TimeProvider time)
    {
        var http = context.HttpContext;
        var usedDpopScheme = http.Items.ContainsKey(SchemeItem);
        if (context.SecurityToken is not JsonWebToken token)
        {
            // Can't read cnf: fail closed rather than accept a token that may be bound.
            return "The token could not be checked for a DPoP binding.";
        }

        string? jkt = null;
        if (token.TryGetPayloadValue<JsonElement>("cnf", out var cnf))
        {
            if (cnf.ValueKind != JsonValueKind.Object || !cnf.TryGetProperty("jkt", out var thumbprint) || thumbprint.ValueKind != JsonValueKind.String)
            {
                // Bound some other way (mTLS x5t#S256, …), which this service can't check.
                return "The token's key binding is not supported.";
            }

            jkt = thumbprint.GetString();
        }

        if (jkt is null)
        {
            return usedDpopScheme ? "The token is not DPoP-bound."
                : mode == DpopMode.Required ? "A DPoP-bound token is required."
                : null;
        }

        if (!usedDpopScheme)
        {
            return "A DPoP-bound token must be sent with the DPoP scheme.";
        }

        var proofs = http.Request.Headers[DpopProofValidator.HeaderName];
        if (proofs.Count != 1)
        {
            return "Send exactly one DPoP proof.";
        }

        var target = new Uri($"{http.Request.Scheme}://{http.Request.Host}{http.Request.PathBase}{http.Request.Path}");
        var now = time.GetUtcNow();
        var (proof, error) = DpopProofValidator.Validate(proofs[0], http.Request.Method, target, now, Window, token.EncodedToken);
        if (proof is null)
        {
            return error;
        }

        if (!string.Equals(proof.Jkt, jkt, StringComparison.Ordinal))
        {
            return "The DPoP proof is signed by another key than the token is bound to.";
        }

        return await http.RequestServices.GetRequiredService<IReplayCache>()
                .TryAddAsync(ReplayKeys.For("dpop", proof.Jkt + "\n" + proof.Jti), now + Window + Window, http.RequestAborted).ConfigureAwait(false)
            ? null
            : "This DPoP proof was already used.";
    }
}

using System.Text.Json;
using JeffOps.Authentication.Abstractions.Dpop;
using JeffOps.Authentication.Abstractions.Replay;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
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
    private const string NonceItem = "jeffops:dpop:use-nonce";
    private const string NoncePurpose = "JeffOps.Dpop.ResourceNonce";
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    public static void Attach(JwtBearerOptions jwt, DpopMode mode, TimeProvider time, bool requireNonce = false)
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
            if (await CheckAsync(context, mode, time, requireNonce).ConfigureAwait(false) is { } failure)
            {
                context.HttpContext.Items[FailedItem] = true;
                context.Fail(failure);
                return;
            }

            await validated(context).ConfigureAwait(false);
        };

        events.OnChallenge = async context =>
        {
            if (context.HttpContext.Items.ContainsKey(NonceItem))
            {
                context.Response.Headers.WWWAuthenticate = Microsoft.Extensions.Primitives.StringValues.Concat(
                    context.Response.Headers.WWWAuthenticate,
                    $"{DpopProofValidator.Scheme} error=\"use_dpop_nonce\", error_description=\"Resend the request with the DPoP-Nonce value in the proof.\"");
            }
            else if (context.HttpContext.Items.ContainsKey(FailedItem) || mode == DpopMode.Required)
            {
                context.Response.Headers.WWWAuthenticate = Microsoft.Extensions.Primitives.StringValues.Concat(
                    context.Response.Headers.WWWAuthenticate,
                    $"{DpopProofValidator.Scheme} error=\"invalid_token\", algs=\"{string.Join(' ', DpopProofValidator.Algorithms)}\"");
            }

            await challenge(context).ConfigureAwait(false);
        };

        jwt.Events = events;
    }

    private static async Task<string?> CheckAsync(TokenValidatedContext context, DpopMode mode, TimeProvider time, bool requireNonce)
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

        // Server nonces: every answer carries a fresh one; a proof without a valid one is turned away with it.
        if (requireNonce)
        {
            var nonces = http.RequestServices.GetRequiredService<IDataProtectionProvider>().CreateProtector(NoncePurpose);
            http.Response.Headers[DpopProofValidator.NonceHeaderName] = DpopNonces.Issue(nonces, now);
            if (!DpopNonces.IsValid(nonces, proof.Nonce, now))
            {
                http.Items[NonceItem] = true;
                return "The DPoP proof needs the nonce in the DPoP-Nonce header.";
            }
        }

        if (!http.RequestServices.GetRequiredService<DpopKeyQuota>().TryTake(proof.Jkt))
        {
            return "Too many DPoP proofs for this key; slow down.";
        }

        return await http.RequestServices.GetRequiredService<IReplayCache>()
                .TryAddAsync(ReplayKeys.For("dpop", proof.Jkt + "\n" + proof.Jti), DpopProofValidator.ReplayExpiry(proof, Window), http.RequestAborted).ConfigureAwait(false)
            ? null
            : "This DPoP proof was already used.";
    }
}

/// <summary>
/// At most <see cref="AuthenticationClientOptions.DpopProofsPerKeyPerMinute"/> proofs per key a minute on this instance, so
/// one client can't fill the replay cache all clients share. Counted per calendar minute; counters of past minutes are
/// dropped once a minute.
/// </summary>
internal sealed class DpopKeyQuota(TimeProvider time, Microsoft.Extensions.Options.IOptions<AuthenticationClientOptions> options)
{
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, Counter> _counters = new(StringComparer.Ordinal);
    private long _sweptMinute;

    public bool TryTake(string jkt)
    {
        var minute = time.GetUtcNow().ToUnixTimeSeconds() / 60;
        var swept = Interlocked.Read(ref _sweptMinute);
        if (minute > swept && Interlocked.CompareExchange(ref _sweptMinute, minute, swept) == swept)
        {
            foreach (var entry in _counters)
            {
                if (Volatile.Read(ref entry.Value.Minute) < minute)
                {
                    _counters.TryRemove(entry);
                }
            }
        }

        var counter = _counters.GetOrAdd(jkt, static _ => new Counter());
        lock (counter)
        {
            if (counter.Minute != minute)
            {
                counter.Minute = minute;
                counter.Count = 0;
            }

            return ++counter.Count <= options.Value.DpopProofsPerKeyPerMinute;
        }
    }

    private sealed class Counter
    {
        public long Minute;
        public int Count;
    }
}

/// <summary>Server-issued DPoP nonces (RFC 9449 §9): Data-Protected issue times, valid for five minutes.</summary>
internal static class DpopNonces
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    public static string Issue(IDataProtector protector, DateTimeOffset now) =>
        DpopProofValidator.Base64Url(protector.Protect(BitConverter.GetBytes(now.ToUnixTimeSeconds())));

    public static bool IsValid(IDataProtector protector, string? nonce, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(nonce) || nonce.Length > 512)
        {
            return false;
        }

        try
        {
            var base64 = nonce.Replace('-', '+').Replace('_', '/');
            base64 = base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '=');
            var issued = DateTimeOffset.FromUnixTimeSeconds(BitConverter.ToInt64(protector.Unprotect(Convert.FromBase64String(base64))));
            return issued <= now + TimeSpan.FromMinutes(1) && now - issued <= Lifetime;
        }
        catch (Exception exception) when (exception is FormatException or System.Security.Cryptography.CryptographicException or ArgumentException)
        {
            return false;
        }
    }
}

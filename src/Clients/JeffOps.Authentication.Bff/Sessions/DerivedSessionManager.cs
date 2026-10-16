using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using static OpenIddict.Client.OpenIddictClientModels;

namespace JeffOps.Authentication.Bff.Sessions;

/// <summary>The outcome of starting or re-minting a derived session.</summary>
public enum DerivedOutcome
{
    /// <summary>The derived session was started, or its token minted again.</summary>
    Started,

    /// <summary>The token server refused (grant over, relationship gone, ...): nothing to retry.</summary>
    Refused,

    /// <summary>The token server or session store could not be reached: retry shortly.</summary>
    Unavailable,

    /// <summary>The own session is gone: sign in again.</summary>
    SignedOut,
}

/// <summary>The result of starting or re-minting a derived session.</summary>
/// <param name="Outcome">What happened.</param>
/// <param name="Id">The new derived session's id, for the acting cookie; set when a session was started.</param>
/// <param name="Session">The derived session; set when the outcome is <see cref="DerivedOutcome.Started"/>.</param>
/// <param name="Error">The token server's OAuth error code when it refused.</param>
public sealed record DerivedStart(DerivedOutcome Outcome, string? Id = null, BffSession? Session = null, string? Error = null);

/// <summary>
/// Derived sessions (impersonation, tenant switch). Tokens are minted at the token server with the extension grant and the own
/// session's access token as <c>actor_token</c>, and minted again before they expire — single-flight per session — so the
/// token server re-checks the grant every few minutes. A derived session is only ever used next to the own session it was
/// started from, compared in constant time on the own session's store key.
/// </summary>
public sealed partial class DerivedSessionManager(
    BffSessionStore store,
    BffSessionManager sessions,
    OpenIddictClientService client,
    IMemoryCache local,
    IOptions<BffOptions> options,
    TimeProvider time,
    ILogger<DerivedSessionManager> logger)
{
    /// <summary>The <see cref="BffSession.Kind"/> of an impersonation session.</summary>
    public const string Impersonation = "impersonation";
    /// <summary>The <see cref="BffSession.Kind"/> of a tenant-switch session.</summary>
    public const string TenantSwitch = "tenant-switch";

    private static readonly SemaphoreSlim[] MintStripes = [.. Enumerable.Range(0, 64).Select(_ => new SemaphoreSlim(1, 1))];
    private static readonly TimeSpan Backoff = TimeSpan.FromSeconds(5);

    /// <summary>Starts an impersonation session against an approved grant.</summary>
    public Task<DerivedStart> StartImpersonationAsync(string ownerId, string grantId, CancellationToken cancellationToken) =>
        StartAsync(ownerId, Impersonation, grantId, cancellationToken);

    /// <summary>Starts a session acting in <paramref name="tenantId"/>.</summary>
    public Task<DerivedStart> StartTenantSwitchAsync(string ownerId, string tenantId, CancellationToken cancellationToken) =>
        StartAsync(ownerId, TenantSwitch, tenantId, cancellationToken);

    /// <summary>
    /// The derived session <paramref name="id"/> with a fresh token, or null when it is over or doesn't belong to
    /// <paramref name="ownerId"/>. A refused re-mint ends it; an unreachable token server keeps it until its token expires.
    /// </summary>
    public async Task<BffSession?> GetFreshAsync(string id, string ownerId, CancellationToken cancellationToken)
    {
        var session = await store.GetAsync(id, cancellationToken).ConfigureAwait(false);
        if (session is null || !BelongsTo(session, ownerId))
        {
            return null;
        }

        if (!NeedsMint(session) || local.TryGetValue(BackoffKey(id), out _))
        {
            return session.AccessExpiresAt > time.GetUtcNow() ? session : null;
        }

        var gate = MintStripes[(uint)StringComparer.Ordinal.GetHashCode(id) % (uint)MintStripes.Length];
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            session = await store.GetAsync(id, cancellationToken).ConfigureAwait(false);
            if (session is null || !NeedsMint(session))
            {
                return session;
            }

            var minted = await MintAsync(ownerId, session.Kind!, session.GrantId ?? session.ActingTenantId!, cancellationToken).ConfigureAwait(false);
            switch (minted.Outcome)
            {
                case DerivedOutcome.Started:
                    var refreshed = session with { AccessToken = minted.Session!.AccessToken, AccessExpiresAt = minted.Session.AccessExpiresAt };
                    await store.UpdateAsync(id, refreshed, cancellationToken).ConfigureAwait(false);
                    return refreshed;
                case DerivedOutcome.Unavailable:
                    local.Set(BackoffKey(id), true, Backoff);
                    return session.AccessExpiresAt > time.GetUtcNow() ? session : null;
                default:
                    LogEnded(logger, session.Kind!, minted.Error);
                    await store.DeleteAsync(id, session.Subject, cancellationToken).ConfigureAwait(false);
                    return null;
            }
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>Deletes a derived session (its grant is ended separately, by the caller).</summary>
    public async Task<BffSession?> EndAsync(string id, CancellationToken cancellationToken)
    {
        var session = await store.GetAsync(id, cancellationToken).ConfigureAwait(false);
        await store.DeleteAsync(id, session?.Subject, cancellationToken).ConfigureAwait(false);
        return session;
    }

    /// <summary>Whether <paramref name="session"/> was started from own session <paramref name="ownerId"/>, compared in constant time.</summary>
    public static bool BelongsTo(BffSession session, string ownerId)
    {
        ArgumentNullException.ThrowIfNull(session);
        return session.OwnerKey is { } owner
            && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(owner), Encoding.ASCII.GetBytes(BffSessionStore.KeyFor(ownerId)));
    }

    private async Task<DerivedStart> StartAsync(string ownerId, string kind, string target, CancellationToken cancellationToken)
    {
        var minted = await MintAsync(ownerId, kind, target, cancellationToken).ConfigureAwait(false);
        if (minted.Outcome != DerivedOutcome.Started)
        {
            return minted;
        }

        var id = await store.CreateAsync(minted.Session!, cancellationToken).ConfigureAwait(false);
        return minted with { Id = id };
    }

    private async Task<DerivedStart> MintAsync(string ownerId, string kind, string target, CancellationToken cancellationToken)
    {
        var settings = options.Value;
        BffSession? owner;
        try
        {
            owner = await sessions.GetFreshAsync(ownerId, readOnlyRequest: false, cancellationToken).ConfigureAwait(false);
        }
        catch (SessionStoreUnavailableException)
        {
            return new DerivedStart(DerivedOutcome.Unavailable);
        }

        if (owner is null || owner.IsDerived)
        {
            return new DerivedStart(DerivedOutcome.SignedOut);
        }

        var parameters = new Dictionary<string, OpenIddictParameter>(StringComparer.Ordinal)
        {
            [OpenIddictConstants.Parameters.ActorToken] = owner.AccessToken,
            [OpenIddictConstants.Parameters.ActorTokenType] = OpenIddictConstants.TokenTypeIdentifiers.AccessToken,
            [kind == Impersonation ? "grant_id" : "target_tenant"] = target,
        };

        CustomGrantAuthenticationResult result;
        try
        {
            result = await client.AuthenticateWithCustomGrantAsync(new CustomGrantAuthenticationRequest
            {
                Issuer = settings.Authority,
                GrantType = kind == Impersonation ? settings.Delegation.ImpersonationGrantType : settings.Delegation.TenantSwitchGrantType,
                Scopes = [.. settings.Scopes.Where(scope => scope is not (OpenIddictConstants.Scopes.OpenId or OpenIddictConstants.Scopes.OfflineAccess))],
                AdditionalTokenRequestParameters = parameters,
                DisableUserInfo = true,
                CancellationToken = cancellationToken,
            }).ConfigureAwait(false);
        }
        catch (OpenIddict.Abstractions.OpenIddictExceptions.ProtocolException exception)
            when (exception.Error is OpenIddictConstants.Errors.InvalidGrant or OpenIddictConstants.Errors.InvalidRequest
                or OpenIddictConstants.Errors.UnauthorizedClient or OpenIddictConstants.Errors.UnsupportedGrantType)
        {
            return new DerivedStart(DerivedOutcome.Refused, Error: exception.Error);
        }
#pragma warning disable CA1031 // Anything else is an outage, not a verdict.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogUnavailable(logger, exception);
            return new DerivedStart(DerivedOutcome.Unavailable);
        }

        var now = time.GetUtcNow();
        var lifetime = kind == Impersonation ? settings.Delegation.ImpersonationLifetime : settings.Delegation.TenantSwitchLifetime;
        var ends = now + lifetime < owner.SessionEndsAt ? now + lifetime : owner.SessionEndsAt;
        var derived = new BffSession(owner.Subject, result.AccessToken, null, null, result.AccessTokenExpirationDate ?? now.AddMinutes(3), ends)
        {
            Kind = kind,
            OwnerKey = BffSessionStore.KeyFor(ownerId),
            GrantId = kind == Impersonation ? target : null,
            ActingTenantId = kind == TenantSwitch ? target : null,
        };
        return new DerivedStart(DerivedOutcome.Started, Session: derived);
    }

    private bool NeedsMint(BffSession session) => time.GetUtcNow() + options.Value.RefreshBeforeExpiry >= session.AccessExpiresAt;

    private static string BackoffKey(string id) => "jeffops:bff:derived-backoff:" + id;

    [LoggerMessage(EventId = 9121, Level = LogLevel.Information, Message = "A {Kind} session ended: the token server refused to mint again ({Error}).")]
    private static partial void LogEnded(ILogger logger, string kind, string? error);

    [LoggerMessage(EventId = 9122, Level = LogLevel.Warning, Message = "Minting a derived session token failed; the token server seems unavailable.")]
    private static partial void LogUnavailable(ILogger logger, Exception exception);
}

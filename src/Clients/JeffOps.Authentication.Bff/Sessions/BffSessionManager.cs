using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Client;
using static OpenIddict.Client.OpenIddictClientModels;

namespace JeffOps.Authentication.Bff.Sessions;

/// <summary>
/// Reads sessions and keeps their access tokens fresh. Refreshing is single-flight per session (striped locks), because
/// refresh tokens rotate and a second concurrent redemption would revoke the chain. A refused refresh ends the session; an
/// unreachable token server is not a verdict, so the current session is kept and retried after a short backoff.
/// </summary>
public sealed partial class BffSessionManager(
    BffSessionStore store,
    OpenIddictClientService client,
    IMemoryCache local,
    IOptions<BffOptions> options,
    TimeProvider time,
    ILogger<BffSessionManager> logger)
{
    private static readonly SemaphoreSlim[] RefreshStripes = [.. Enumerable.Range(0, 64).Select(_ => new SemaphoreSlim(1, 1))];
    private static readonly TimeSpan LocalLifetime = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan RefreshBackoff = TimeSpan.FromSeconds(5);

    /// <summary>The session with a fresh access token, or null when there is none (signed out, expired, refused).</summary>
    public async Task<BffSession?> GetFreshAsync(string id, bool readOnlyRequest, CancellationToken cancellationToken)
    {
        if (local.TryGetValue(LocalKey(id), out BffSession? hot) && hot is not null && !NeedsRefresh(hot))
        {
            return hot;
        }

        var session = await ReadAsync(id, readOnlyRequest, cancellationToken).ConfigureAwait(false);
        if (session is null || !NeedsRefresh(session) || local.TryGetValue(BackoffKey(id), out _))
        {
            Remember(id, session);
            return session;
        }

        var gate = RefreshStripes[(uint)StringComparer.Ordinal.GetHashCode(id) % (uint)RefreshStripes.Length];
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Another request may have refreshed it while this one waited.
            session = await ReadAsync(id, readOnlyRequest, cancellationToken).ConfigureAwait(false);
            if (session is null || !NeedsRefresh(session))
            {
                Remember(id, session);
                return session;
            }

            var refreshed = await RefreshAsync(id, session, cancellationToken).ConfigureAwait(false);
            Remember(id, refreshed);
            return refreshed;
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>Ends the session: revokes its refresh token at the token server (best effort) and deletes it.</summary>
    public async Task EndAsync(string id, CancellationToken cancellationToken)
    {
        var session = await store.GetAsync(id, cancellationToken).ConfigureAwait(false);
        Forget(id);
        if (session is null)
        {
            return;
        }

        if (session.RefreshToken is { Length: > 0 } refreshToken)
        {
            try
            {
                await client.RevokeTokenAsync(new RevocationRequest
                {
                    Issuer = options.Value.Authority,
                    Token = refreshToken,
                    TokenTypeHint = "refresh_token",
                    CancellationToken = cancellationToken,
                }).ConfigureAwait(false);
            }
#pragma warning disable CA1031 // Revocation is best effort: the session is deleted either way and the token expires.
            catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
            {
                LogRevocationFailed(logger, exception);
            }
        }

        await store.DeleteAsync(id, session.Subject, cancellationToken).ConfigureAwait(false);
    }

    public void Forget(string id)
    {
        local.Remove(LocalKey(id));
        local.Remove(LastKnownKey(id));
    }

    private async Task<BffSession?> ReadAsync(string id, bool readOnlyRequest, CancellationToken cancellationToken)
    {
        try
        {
            return await store.GetAsync(id, cancellationToken).ConfigureAwait(false);
        }
        catch (SessionStoreUnavailableException) when (readOnlyRequest
            && local.TryGetValue(LastKnownKey(id), out BffSession? known)
            && known is not null
            && known.AccessExpiresAt > time.GetUtcNow())
        {
            // Store outage: a read may use the last known copy while its access token is still valid.
            return known;
        }
    }

    private async Task<BffSession?> RefreshAsync(string id, BffSession session, CancellationToken cancellationToken)
    {
        if (session.RefreshToken is not { Length: > 0 } refreshToken)
        {
            return session.AccessExpiresAt > time.GetUtcNow() ? session : null;
        }

        RefreshTokenAuthenticationResult result;
        try
        {
            result = await client.AuthenticateWithRefreshTokenAsync(new RefreshTokenAuthenticationRequest
            {
                Issuer = options.Value.Authority,
                RefreshToken = refreshToken,
                DisableUserInfo = true,
                CancellationToken = cancellationToken,
            }).ConfigureAwait(false);
        }
        catch (OpenIddict.Abstractions.OpenIddictExceptions.ProtocolException exception) when (IsRefusal(exception))
        {
            LogRefreshRefused(logger, exception.Error);
            await store.DeleteAsync(id, session.Subject, cancellationToken).ConfigureAwait(false);
            Forget(id);
            return null;
        }
#pragma warning disable CA1031 // Anything else is an outage, not a verdict: keep the session, retry shortly.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogRefreshUnavailable(logger, exception);
            local.Set(BackoffKey(id), true, RefreshBackoff);
            return session;
        }

        var refreshed = session with
        {
            AccessToken = result.AccessToken,
            RefreshToken = result.RefreshToken ?? session.RefreshToken,
            AccessExpiresAt = result.AccessTokenExpirationDate ?? time.GetUtcNow().AddMinutes(5),
        };
        await store.UpdateAsync(id, refreshed, cancellationToken).ConfigureAwait(false);
        return refreshed;
    }

    private static bool IsRefusal(OpenIddict.Abstractions.OpenIddictExceptions.ProtocolException exception) =>
        exception.Error is "invalid_grant" or "invalid_client" or "unauthorized_client" or "invalid_request";

    private bool NeedsRefresh(BffSession session) => time.GetUtcNow() + options.Value.RefreshBeforeExpiry >= session.AccessExpiresAt;

    private void Remember(string id, BffSession? session)
    {
        if (session is null)
        {
            return;
        }

        local.Set(LocalKey(id), session, LocalLifetime);
        if (options.Value.StoreOutageGrace > TimeSpan.Zero)
        {
            local.Set(LastKnownKey(id), session, options.Value.StoreOutageGrace);
        }
    }

    private static string LocalKey(string id) => "jeffops:bff:hot:" + id;

    private static string LastKnownKey(string id) => "jeffops:bff:known:" + id;

    private static string BackoffKey(string id) => "jeffops:bff:backoff:" + id;

    [LoggerMessage(EventId = 9101, Level = LogLevel.Information, Message = "The token server refused to refresh a session ({Error}); ending it.")]
    private static partial void LogRefreshRefused(ILogger logger, string? error);

    [LoggerMessage(EventId = 9102, Level = LogLevel.Warning, Message = "Refreshing a session failed; the token server seems unavailable. Retrying shortly.")]
    private static partial void LogRefreshUnavailable(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 9103, Level = LogLevel.Warning, Message = "Revoking a refresh token at sign-out failed; the session is deleted anyway.")]
    private static partial void LogRevocationFailed(ILogger logger, Exception exception);
}

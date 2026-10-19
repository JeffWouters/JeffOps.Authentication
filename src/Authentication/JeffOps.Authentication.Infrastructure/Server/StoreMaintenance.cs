using System.Security.Cryptography;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// Keeps the token store from growing without bound, off the request path. Every minute it deletes expired replay entries,
/// expired external sessions and ended sessions older than <see cref="TokenServerOptions.SessionLifetime"/>, in batches.
/// Every <see cref="TokenServerOptions.PruneInterval"/> it also removes tokens and authorizations that can no longer be
/// used (expired, redeemed, revoked, or of an ended authorization) once they are older than
/// <see cref="TokenServerOptions.PruneAfter"/>. Valid tokens are never removed. Every instance runs it, after a random first
/// delay so instances started together don't run together; a delete is the same from any instance.
/// </summary>
internal sealed partial class StoreMaintenance(
    IServiceScopeFactory scopes,
    IOptions<TokenServerOptions> options,
    TimeProvider time,
    ILogger<StoreMaintenance> logger) : BackgroundService
{
    private static readonly TimeSpan SweepInterval = TimeSpan.FromMinutes(1);
    private const int BatchSize = 5_000;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromMilliseconds(RandomNumberGenerator.GetInt32((int)SweepInterval.TotalMilliseconds + 1)), time, stoppingToken).ConfigureAwait(false);

        var interval = options.Value.PruneInterval;
        var nextPrune = time.GetUtcNow();

        // One delay at a time (not a periodic timer): after a long pause, such as a suspended host, one pass catches up.
        while (!stoppingToken.IsCancellationRequested)
        {
            await SweepAsync(stoppingToken).ConfigureAwait(false);
            if (interval > TimeSpan.Zero && time.GetUtcNow() >= nextPrune)
            {
                await PruneAsync(stoppingToken).ConfigureAwait(false);
                nextPrune = time.GetUtcNow() + interval;
            }

            await Task.Delay(SweepInterval, time, stoppingToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Deletes the short-lived entries nothing reads any more: expired replay entries (an expired one is taken over anyway)
    /// and external sessions (ignored once expired), and ended sessions whose tokens can no longer be refreshed.
    /// </summary>
    internal async Task SweepAsync(CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var nowMs = now.ToUnixTimeMilliseconds();
        var endedBefore = (now - options.Value.SessionLifetime).ToUnixTimeMilliseconds();
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>();
            var replay = await DeleteAsync(db.ReplayEntries.Where(entry => entry.ExpiresAtUnixMs <= nowMs), cancellationToken).ConfigureAwait(false);
            var external = await DeleteAsync(db.ExternalSessions.Where(entry => entry.ExpiresAtUnixMs <= nowMs), cancellationToken).ConfigureAwait(false);
            var ended = await DeleteAsync(db.EndedSessions.Where(session => session.EndedAtUnixMs < endedBefore), cancellationToken).ConfigureAwait(false);
            if (replay + external + ended > 0)
            {
                LogSwept(logger, replay, external, ended);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
#pragma warning disable CA1031 // A failed pass is logged and retried at the next minute.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            LogSweepFailed(logger, exception);
        }
    }

    /// <summary>Deletes in batches, so no single statement holds locks on a large part of a table.</summary>
    private static async Task<int> DeleteAsync<TEntry>(IQueryable<TEntry> expired, CancellationToken cancellationToken)
    {
        var total = 0;
        int deleted;
        do
        {
            deleted = await expired.Take(BatchSize).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
            total += deleted;
        }
        while (deleted == BatchSize);

        return total;
    }

    /// <summary>One pass. A failed pass is logged and tried again at the next interval.</summary>
    internal async Task PruneAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;

        // A redeemed refresh token is kept while it could still be presented (refresh tokens live as long as the session),
        // so presenting it again is still recognised as reuse and revokes the chain.
        var retention = settings.PruneAfter > settings.SessionLifetime ? settings.PruneAfter : settings.SessionLifetime;
        var threshold = time.GetUtcNow() - retention;
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            var tokens = await scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>().PruneAsync(threshold, cancellationToken).ConfigureAwait(false);
            var authorizations = await scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>().PruneAsync(threshold, cancellationToken).ConfigureAwait(false);
            if (tokens + authorizations > 0)
            {
                LogPruned(logger, tokens, authorizations, threshold);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
#pragma warning disable CA1031 // A failed pass is logged and retried at the next interval.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            LogFailed(logger, exception);
        }
    }

    [LoggerMessage(EventId = 8801, Level = LogLevel.Information, Message = "Pruned {Tokens} tokens and {Authorizations} authorizations no longer usable since before {Threshold:o}.")]
    private static partial void LogPruned(ILogger logger, long tokens, long authorizations, DateTimeOffset threshold);

    [LoggerMessage(EventId = 8802, Level = LogLevel.Error, Message = "Pruning the token store failed; retrying at the next interval.")]
    private static partial void LogFailed(ILogger logger, Exception exception);

    [LoggerMessage(EventId = 8803, Level = LogLevel.Debug, Message = "Deleted {Replay} expired replay entries, {External} expired external sessions and {Ended} old ended sessions.")]
    private static partial void LogSwept(ILogger logger, int replay, int external, int ended);

    [LoggerMessage(EventId = 8804, Level = LogLevel.Error, Message = "Deleting expired replay entries and sessions failed; retrying at the next minute.")]
    private static partial void LogSweepFailed(ILogger logger, Exception exception);
}

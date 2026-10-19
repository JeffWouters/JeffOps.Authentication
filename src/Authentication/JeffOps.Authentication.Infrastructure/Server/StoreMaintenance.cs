using System.Security.Cryptography;
using JeffOps.Authentication.Application;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// Keeps the token store from growing without bound: every <see cref="TokenServerOptions.PruneInterval"/> it removes tokens
/// and authorizations that can no longer be used (expired, redeemed, revoked, or of an ended authorization) once they are
/// older than <see cref="TokenServerOptions.PruneAfter"/>. Valid tokens are never removed. Every instance prunes, after a
/// random first delay so instances started together don't prune together; a delete is the same from any instance.
/// </summary>
internal sealed partial class StoreMaintenance(
    IServiceScopeFactory scopes,
    IOptions<TokenServerOptions> options,
    TimeProvider time,
    ILogger<StoreMaintenance> logger) : BackgroundService
{
    private static readonly TimeSpan MaxFirstDelay = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = options.Value.PruneInterval;
        if (interval <= TimeSpan.Zero)
        {
            return;
        }

        var firstDelay = interval < MaxFirstDelay ? interval : MaxFirstDelay;
        await Task.Delay(TimeSpan.FromMilliseconds(RandomNumberGenerator.GetInt32((int)firstDelay.TotalMilliseconds + 1)), time, stoppingToken).ConfigureAwait(false);

        using var timer = new PeriodicTimer(interval, time);
        do
        {
            await PruneAsync(stoppingToken).ConfigureAwait(false);
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
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
}

using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Permissions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace JeffOps.Authorization.AspNetCore.Data;

/// <summary>The permissions a service declares, pushed to the registry at startup.</summary>
public sealed record PermissionManifest(string Source, IReadOnlyList<PermissionDefinition> Definitions);

/// <summary>
/// Declares the service's permissions to the management registry, off the startup path: the management service is often
/// still starting when this service boots, so it retries with backoff. It never blocks or fails startup — enforcement
/// doesn't depend on the registry, only role administration (the permission picker and typo guard) does.
/// </summary>
internal sealed partial class PermissionRegistration(
    PermissionManifest manifest,
    IPermissionRegistry registry,
    TimeProvider time,
    ILogger<PermissionRegistration> logger) : BackgroundService
{
    private const int MaxAttempts = 10;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (manifest.Definitions.Count == 0)
        {
            // An empty batch would mark every permission of this source stale.
            LogNothingToRegister(logger, manifest.Source);
            return;
        }

        for (var attempt = 1; attempt <= MaxAttempts && !stoppingToken.IsCancellationRequested; attempt++)
        {
            try
            {
                await registry.RegisterAsync(new RegisterPermissionsRequest(manifest.Source, manifest.Definitions), stoppingToken).ConfigureAwait(false);
                LogRegistered(logger, manifest.Definitions.Count, manifest.Source);
                return;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
#pragma warning disable CA1031 // Registration is best effort; every failure is logged and retried.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                LogAttemptFailed(logger, exception, manifest.Source, attempt);
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(Math.Min(30, attempt * 3)), time, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }

        LogGaveUp(logger, manifest.Source);
    }

    [LoggerMessage(EventId = 7111, Level = LogLevel.Warning, Message = "No permission definitions declared for {Source}; skipping registration.")]
    private static partial void LogNothingToRegister(ILogger logger, string source);

    [LoggerMessage(EventId = 7112, Level = LogLevel.Information, Message = "Registered {Count} permission definitions for {Source}.")]
    private static partial void LogRegistered(ILogger logger, int count, string source);

    [LoggerMessage(EventId = 7113, Level = LogLevel.Warning, Message = "Permission registration for {Source} failed (attempt {Attempt}); retrying.")]
    private static partial void LogAttemptFailed(ILogger logger, Exception exception, string source, int attempt);

    [LoggerMessage(EventId = 7114, Level = LogLevel.Warning, Message = "Permission registration for {Source} gave up after retries; enforcement is unaffected.")]
    private static partial void LogGaveUp(ILogger logger, string source);
}

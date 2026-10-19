using JeffOps.Authentication.Abstractions.Notifications;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Delegation.Application;
using JeffOps.Authentication.Delegation.Application.Features.Impersonation;
using JeffOps.Authentication.Delegation.Application.Features.Maintenance;
using JeffOps.Authentication.Delegation.Application.Features.TenantAccess;
using JeffOps.Authentication.Delegation.Application.Features.Tokens;
using JeffOps.Authentication.SharedKernel.DependencyInjection;
using JeffOps.Authentication.SharedKernel.Handlers;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace JeffOps.Authentication.Delegation.Infrastructure;

/// <summary>Returned by <see cref="DelegationServiceCollectionExtensions.AddDelegation"/>.</summary>
public sealed record DelegationBuilder(IServiceCollection Services)
{
    /// <summary>
    /// Configures the delegation store's database provider. Contexts are pooled (one per concurrent request, reused): <paramref name="configure"/> runs once, with the root service provider, so it must not resolve scoped services.
    /// </summary>
    public DelegationBuilder UseDatabase(Action<IServiceProvider, DbContextOptionsBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.AddDbContextPool<DelegationDbContext>((provider, options) =>
        {
            // Every SQL command at Debug, not Information: a host's default level would otherwise format each one. Set first, so
            // the host's own configuration wins.
            options.ConfigureWarnings(warnings => warnings.Log((RelationalEventId.CommandExecuted, LogLevel.Debug)));
            configure(provider, options);
        });
        return this;
    }

    /// <summary>Uses the host's partner relationships (which tenants each organization manages, and lockbox tenants).</summary>
    public DelegationBuilder UseDirectory<TDirectory>()
        where TDirectory : class, IDelegationDirectory
    {
        Services.RemoveAll<IDelegationDirectory>();
        Services.AddScoped<IDelegationDirectory, TDirectory>();
        return this;
    }
}

/// <summary>Prepares the delegation database before use, for example by applying migrations.</summary>
public interface IDelegationDatabaseInitializer
{
    Task InitializeAsync(CancellationToken cancellationToken);
}

public static class DelegationServiceCollectionExtensions
{
    /// <summary>
    /// Adds delegated access to the token server (docs/DESIGN.md §12): impersonation with target approval and break-glass,
    /// lockbox tenant access, and tenant switch, minted through the extension grants <c>impersonation</c> and
    /// <c>tenant-switch</c>. Map the endpoints with <c>MapJeffOpsDelegation</c>, add a database (for example
    /// <c>AddDelegationSqlServer</c>), and plug in the host's partner relationships with <see cref="DelegationBuilder.UseDirectory{T}"/>.
    /// Options bind from <see cref="DelegationOptions.SectionName"/>.
    /// </summary>
    public static DelegationBuilder AddDelegation(this AuthenticationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.Services.AddJeffOpsDelegation(builder.Configuration);
    }

    /// <summary>The registrations behind <see cref="AddDelegation"/>, for hosts composing the token server by hand.</summary>
    public static DelegationBuilder AddJeffOpsDelegation(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<DelegationOptions>().Bind(configuration.GetSection(DelegationOptions.SectionName));
        services.TryAddScoped<IDelegationDirectory, NoDelegations>();
        services.TryAddSingleton<INotifier, LoggingNotifier>();
        services.TryAddScoped<IImpersonationGrantRepository, ImpersonationGrantRepository>();
        services.TryAddScoped<ITenantAccessGrantRepository, TenantAccessGrantRepository>();
        services.TryAddScoped<IDueGrantSource, DueGrantSource>();
        services.TryAddScoped<IDelegationUnitOfWork, DelegationUnitOfWork>();

        services
            .AddHandler<RequestImpersonationHandler>()
            .AddHandler<DecideImpersonationHandler>()
            .AddHandler<EndImpersonationHandler>()
            .AddHandler<GetImpersonationHandler>()
            .AddHandler<ListImpersonationsHandler>()
            .AddHandler<RequestTenantAccessHandler>()
            .AddHandler<DecideTenantAccessHandler>()
            .AddHandler<EndTenantAccessHandler>()
            .AddHandler<ListTenantAccessHandler>()
            .AddHandler<ExpireGrantsHandler>();
        services.AddDomainEventHandler<DelegationEventPublishers>();

        services.AddScoped<IExtensionGrantHandler, MintImpersonationTokenHandler>();
        services.AddScoped<IExtensionGrantHandler, MintTenantSwitchTokenHandler>();
        services.AddSingleton(new ExtensionGrantRegistration(DelegationOptions.ImpersonationGrant));
        services.AddSingleton(new ExtensionGrantRegistration(DelegationOptions.TenantSwitchGrant));

        services.AddHostedService<DelegationMaintenance>();
        return new DelegationBuilder(services);
    }
}

/// <summary>Initializes the database at startup, then marks overdue grants expired every five minutes.</summary>
internal sealed partial class DelegationMaintenance(IServiceProvider services, TimeProvider time, ILogger<DelegationMaintenance> logger) : BackgroundService
{
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await using (var scope = services.CreateAsyncScope())
        {
            foreach (var initializer in scope.ServiceProvider.GetServices<IDelegationDatabaseInitializer>())
            {
                await initializer.InitializeAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(5), time);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await using var scope = services.CreateAsyncScope();
                var expired = await scope.ServiceProvider.GetRequiredService<ICommandHandler<ExpireGrantsCommand, int>>()
                    .HandleAsync(new ExpireGrantsCommand(), stoppingToken).ConfigureAwait(false);
                if (expired.IsSuccess && expired.Value > 0)
                {
                    LogExpired(logger, expired.Value);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
#pragma warning disable CA1031 // A failed pass is logged and retried at the next tick.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                LogFailed(logger, exception);
            }
        }
    }

    [LoggerMessage(EventId = 6301, Level = LogLevel.Information, Message = "Marked {Count} delegation grants expired.")]
    private static partial void LogExpired(ILogger logger, int count);

    [LoggerMessage(EventId = 6302, Level = LogLevel.Error, Message = "Expiring delegation grants failed; retrying at the next tick.")]
    private static partial void LogFailed(ILogger logger, Exception exception);
}

internal sealed partial class LoggingNotifier(ILogger<LoggingNotifier> logger) : INotifier
{
    public Task NotifyAsync(UserNotification notification, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(notification);
        Log(logger, notification.Kind, notification.UserId, notification.Priority);
        return Task.CompletedTask;
    }

    [LoggerMessage(EventId = 6311, Level = LogLevel.Warning, Message = "Notification {Kind} for user {UserId} ({Priority}) has no delivery channel; register an INotifier.")]
    private static partial void Log(ILogger logger, string kind, Guid userId, NotificationPriority priority);
}

using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authorization.Application;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Application.DependencyInjection;
using JeffOps.Authorization.Application.Features.Assignments;
using JeffOps.Authorization.Application.Management;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace JeffOps.Authorization.Infrastructure.DependencyInjection;

/// <summary>Returned by <see cref="AuthorizationManagementServiceCollectionExtensions.AddJeffOpsAuthorization"/>.</summary>
public sealed record AuthorizationManagementBuilder(IServiceCollection Services, IConfiguration Configuration)
{
    /// <summary>
    /// Configures the store's database provider. Contexts are pooled (one per concurrent request, reused): <paramref name="configure"/> runs once, with the root service provider, so it must not resolve scoped services.
    /// </summary>
    public AuthorizationManagementBuilder UseDatabase(Action<IServiceProvider, DbContextOptionsBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.AddDbContextPool<AuthorizationDbContext>((provider, options) =>
        {
            // Every SQL command at Debug, not Information: a host's default level would otherwise format each one. Set first, so
            // the host's own configuration wins.
            options.ConfigureWarnings(warnings => warnings.Log((RelationalEventId.CommandExecuted, LogLevel.Debug)));
            configure(provider, options);
        });
        return this;
    }
}

/// <summary>Prepares the database before seeding, for example by applying migrations.</summary>
public interface IAuthorizationDatabaseInitializer
{
    /// <summary>Brings the database up to date. Runs once at startup, before the management store is seeded.</summary>
    Task InitializeAsync(CancellationToken cancellationToken);
}

/// <summary>Registers authorization management.</summary>
public static class AuthorizationManagementServiceCollectionExtensions
{
    /// <summary>
    /// Adds authorization management (docs/DESIGN.md §11.5): the management use cases, the store, the startup seeder, the
    /// expiry sweeper, and the in-process data source, so this host's own permission checks read its store instead of calling
    /// itself. Add a database (for example <c>AddSqlServerPersistence</c>), and permission authorization
    /// (<c>AddJeffOpsPermissionAuthorization</c>) so management endpoints get step-up and impersonation limits too.
    /// Options bind from <see cref="ManagementOptions.SectionName"/>.
    /// </summary>
    public static AuthorizationManagementBuilder AddJeffOpsAuthorization(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<ManagementOptions>().Bind(configuration.GetSection(ManagementOptions.SectionName));
        services.AddJeffOpsAuthorizationApplication();

        services.TryAddScoped<IRoleRepository, RoleRepository>();
        services.TryAddScoped<IAuthorizationReads, AuthorizationReads>();
        services.TryAddScoped<IAssignmentRepository, AssignmentRepository>();
        services.TryAddScoped<IRoleChangeRepository, RoleChangeRepository>();
        services.TryAddScoped<IApprovalSettingRepository, ApprovalSettingRepository>();
        services.TryAddScoped<IPolicyRepository, PolicyRepository>();
        services.TryAddScoped<IScopeRepository, ScopeRepository>();
        services.TryAddScoped<IRegisteredPermissionRepository, RegisteredPermissionRepository>();
        services.TryAddScoped<IGroupAssignmentRepository, GroupAssignmentRepository>();
        services.TryAddScoped<IGroupMemberRepository, GroupMemberRepository>();
        services.TryAddScoped<IUnitOfWork, EfUnitOfWork>();
        services.TryAddSingleton<IAuditSink, LoggingAuditSink>();
        // Default: deliver to this host's own handlers (its decision cache). Register a broker publisher to reach other services.
        services.TryAddSingleton<IEventPublisher, InProcessEventPublisher>();

        // This host reads its own store for its decisions (replacing the HTTP data source of resource services).
        services.RemoveAll<IAuthorizationDataSource>();
        services.AddScoped<IAuthorizationDataSource>(provider => provider.GetRequiredService<StoreDataSource>());

        services.AddHostedService<ManagementStartup>();
        services.AddHostedService<ExpiredAssignmentSweeper>();
        return new AuthorizationManagementBuilder(services, configuration);
    }
}

/// <summary>Runs database initializers, then seeds built-in scopes and roles.</summary>
internal sealed class ManagementStartup(IServiceProvider services) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = services.CreateAsyncScope();
        foreach (var initializer in scope.ServiceProvider.GetServices<IAuthorizationDatabaseInitializer>())
        {
            await initializer.InitializeAsync(cancellationToken).ConfigureAwait(false);
        }

        await scope.ServiceProvider.GetRequiredService<ManagementSeeder>().SeedAsync(cancellationToken).ConfigureAwait(false);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>Removes expired assignments every five minutes (decisions already ignore them; this cleans up and announces).</summary>
internal sealed partial class ExpiredAssignmentSweeper(IServiceProvider services, TimeProvider time, ILogger<ExpiredAssignmentSweeper> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(5), time);
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await using var scope = services.CreateAsyncScope();
                var swept = await scope.ServiceProvider.GetRequiredService<ICommandHandler<SweepExpiredAssignmentsCommand, int>>()
                    .HandleAsync(new SweepExpiredAssignmentsCommand(), stoppingToken).ConfigureAwait(false);
                if (swept.IsSuccess && swept.Value > 0)
                {
                    LogSwept(logger, swept.Value);
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

    [LoggerMessage(EventId = 7201, Level = LogLevel.Information, Message = "Removed {Count} expired role assignments.")]
    private static partial void LogSwept(ILogger logger, int count);

    [LoggerMessage(EventId = 7202, Level = LogLevel.Error, Message = "Sweeping expired role assignments failed; retrying at the next tick.")]
    private static partial void LogFailed(ILogger logger, Exception exception);
}

/// <summary>The default audit sink of authorization management: writes audit records, with their details, to the log.</summary>
internal sealed partial class LoggingAuditSink(ILogger<LoggingAuditSink> logger) : IAuditSink
{
    public Task WriteAsync(AuditRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);

        var details = FormatDetails(record.Details);
        if (record.Severity == AuditSeverity.Warning)
        {
            LogWarning(logger, record.Action, record.TargetType, record.TargetId, record.ActorId, record.TenantId, details);
        }
        else
        {
            Log(logger, record.Action, record.TargetType, record.TargetId, record.ActorId, record.TenantId, details);
        }

        return Task.CompletedTask;
    }

    /// <summary><c>key=value</c> pairs in key order, with control characters blanked so a detail can't forge a log line.</summary>
    internal static string FormatDetails(IReadOnlyDictionary<string, string?> details) =>
        string.Join(", ", details.OrderBy(pair => pair.Key, StringComparer.Ordinal).Select(pair => $"{Clean(pair.Key)}={Clean(pair.Value)}"));

    private static string Clean(string? value) =>
        value is null ? string.Empty : string.Create(value.Length, value, static (span, text) =>
        {
            for (var i = 0; i < text.Length; i++)
            {
                span[i] = char.IsControl(text[i]) ? ' ' : text[i];
            }
        });

    [LoggerMessage(EventId = 7211, Level = LogLevel.Information, Message = "Audit {Action} on {TargetType} {TargetId} by {ActorId} in {TenantId}: {Details}")]
    private static partial void Log(ILogger logger, string action, string targetType, string targetId, Guid? actorId, Guid? tenantId, string details);

    [LoggerMessage(EventId = 7213, Level = LogLevel.Warning, Message = "Audit {Action} on {TargetType} {TargetId} by {ActorId} in {TenantId}: {Details}")]
    private static partial void LogWarning(ILogger logger, string action, string targetType, string targetId, Guid? actorId, Guid? tenantId, string details);
}

/// <summary>
/// Delivers integration events to this host's own <see cref="IIntegrationEventHandler{TEvent}"/>s, such as the decision
/// cache invalidators when permission authorization is co-hosted. Replace it with a broker publisher to reach other services
/// (whose subscription should include this host).
/// </summary>
internal sealed partial class InProcessEventPublisher(IServiceScopeFactory scopes, ILogger<InProcessEventPublisher> logger) : IEventPublisher
{
    public async Task PublishAsync(IntegrationEvent integrationEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(integrationEvent);

        var handlerType = typeof(IIntegrationEventHandler<>).MakeGenericType(integrationEvent.GetType());
        var method = handlerType.GetMethod(nameof(IIntegrationEventHandler<IntegrationEvent>.HandleAsync))!;
        await using var scope = scopes.CreateAsyncScope();
        var handlers = scope.ServiceProvider.GetServices(handlerType).ToList();
        foreach (var handler in handlers)
        {
            await ((Task)method.Invoke(handler, [integrationEvent, cancellationToken])!).ConfigureAwait(false);
        }

        Log(logger, integrationEvent.Type, handlers.Count);
    }

    [LoggerMessage(EventId = 7212, Level = LogLevel.Debug, Message = "Integration event {Type} delivered to {Count} local handlers.")]
    private static partial void Log(ILogger logger, string type, int count);
}

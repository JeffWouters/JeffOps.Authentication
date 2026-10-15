using JeffOps.Authentication.Abstractions.Notifications;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.LocalAccounts.Application;
using JeffOps.Authentication.LocalAccounts.Application.Features.Authenticator;
using JeffOps.Authentication.LocalAccounts.Application.Features.Passkeys;
using JeffOps.Authentication.LocalAccounts.Application.Features.Passwords;
using JeffOps.Authentication.LocalAccounts.Application.Features.Registration;
using JeffOps.Authentication.LocalAccounts.Application.Features.SignIn;
using JeffOps.Authentication.SharedKernel.DependencyInjection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.LocalAccounts.Infrastructure;

/// <summary>Returned by <see cref="LocalAccountsServiceCollectionExtensions.AddLocalAccounts"/>.</summary>
public sealed record LocalAccountsBuilder(IServiceCollection Services)
{
    public LocalAccountsBuilder UseDatabase(Action<IServiceProvider, DbContextOptionsBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.AddDbContext<LocalAccountsDbContext>(configure);
        return this;
    }

    /// <summary>Sends account emails (verification, reset) through the host's mail system.</summary>
    public LocalAccountsBuilder UseEmailSender<TSender>()
        where TSender : class, IAccountEmailSender
    {
        Services.RemoveAll<IAccountEmailSender>();
        Services.AddScoped<IAccountEmailSender, TSender>();
        return this;
    }
}

/// <summary>Prepares the local accounts database, for example by applying migrations.</summary>
public interface ILocalAccountsDatabaseInitializer
{
    Task InitializeAsync(CancellationToken cancellationToken);
}

public static class LocalAccountsServiceCollectionExtensions
{
    /// <summary>
    /// Adds local accounts to the token server (docs/DESIGN.md §8.5): passwords (PBKDF2-SHA512, transparent upgrade of older
    /// hashes), progressive lockout, email verification and password reset, authenticator apps with recovery codes, and
    /// passkeys through ASP.NET Core Identity's WebAuthn implementation. Off outside Development unless
    /// <c>JeffOps:LocalAccounts:Enabled</c> is true. Map the endpoints with <c>MapJeffOpsLocalAccounts</c>.
    /// </summary>
    public static LocalAccountsBuilder AddLocalAccounts(this AuthenticationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.Services.AddJeffOpsLocalAccounts(builder.Configuration);
    }

    /// <summary>The registrations behind <see cref="AddLocalAccounts"/>.</summary>
    public static LocalAccountsBuilder AddJeffOpsLocalAccounts(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<LocalAccountOptions>().Bind(configuration.GetSection(LocalAccountOptions.SectionName));
        services.TryAddScoped<ILocalCredentialRepository, LocalCredentialRepository>();
        services.TryAddScoped<IAccountTokenRepository, AccountTokenRepository>();
        services.TryAddScoped<ILocalUnitOfWork, LocalUnitOfWork>();
        services.TryAddSingleton<ITotpSecretProtector, DataProtectionTotpProtector>();
        services.TryAddScoped<IAccountEmailSender, LoggingAccountEmailSender>();
        services.TryAddSingleton<INotifier, LoggingNotifier>();
        services.AddDataProtection();

        services
            .AddHandler<RegisterLocalAccountHandler>()
            .AddHandler<VerifyEmailHandler>()
            .AddHandler<ResendVerificationHandler>()
            .AddHandler<PasswordSignInHandler>()
            .AddHandler<SecondFactorHandler>()
            .AddHandler<ChangePasswordHandler>()
            .AddHandler<RequestPasswordResetHandler>()
            .AddHandler<ResetPasswordHandler>()
            .AddHandler<BeginAuthenticatorHandler>()
            .AddHandler<ConfirmAuthenticatorHandler>()
            .AddHandler<DisableAuthenticatorHandler>()
            .AddHandler<RegenerateRecoveryCodesHandler>()
            .AddHandler<AddPasskeyHandler>()
            .AddHandler<PasskeySignInHandler>()
            .AddHandler<ListPasskeysHandler>()
            .AddHandler<RemovePasskeyHandler>();
        services.AddDomainEventHandler<LocalAccountEvents>();

        // WebAuthn through ASP.NET Core Identity: only its user manager, a narrow store and the passkey handler.
        services.AddIdentityCore<PasskeyUser>().AddUserStore<PasskeyUserStore>();
        services.TryAddScoped<IPasskeyHandler<PasskeyUser>, PasskeyHandler<PasskeyUser>>();
        services.AddOptions<IdentityPasskeyOptions>().Configure<IOptions<LocalAccountOptions>>((passkeys, local) =>
        {
            if (local.Value.PasskeyServerDomain is { Length: > 0 } domain)
            {
                passkeys.ServerDomain = domain;
            }

            if (local.Value.PasskeyAllowedOrigins.Count > 0)
            {
                var allowed = local.Value.PasskeyAllowedOrigins.ToHashSet(StringComparer.OrdinalIgnoreCase);
                passkeys.ValidateOrigin = context => ValueTask.FromResult(!context.CrossOrigin && allowed.Contains(context.Origin));
            }
        });

        services.AddSingleton(provider => new InteractiveSignInMethod(
            "password",
            "/account/local/login",
            IsEnabled(provider.GetRequiredService<IOptions<LocalAccountOptions>>().Value, provider.GetRequiredService<IHostEnvironment>())));

        services.AddHostedService<LocalAccountsStartup>();
        return new LocalAccountsBuilder(services);
    }

    /// <summary>Whether local accounts are on: explicitly configured, or by default in Development only.</summary>
    public static bool IsEnabled(LocalAccountOptions options, IHostEnvironment environment)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(environment);
        return options.Enabled ?? environment.IsDevelopment();
    }
}

internal sealed class LocalAccountsStartup(IServiceProvider services) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = services.CreateAsyncScope();
        foreach (var initializer in scope.ServiceProvider.GetServices<ILocalAccountsDatabaseInitializer>())
        {
            await initializer.InitializeAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

internal sealed partial class LoggingAccountEmailSender(ILogger<LoggingAccountEmailSender> logger, IHostEnvironment environment) : IAccountEmailSender
{
    public Task SendVerificationAsync(string email, Uri link, CancellationToken cancellationToken) => Send("verification", link);

    public Task SendPasswordResetAsync(string email, Uri link, CancellationToken cancellationToken) => Send("password reset", link);

    public Task SendAlreadyRegisteredAsync(string email, CancellationToken cancellationToken) => Send("already registered", null);

    private Task Send(string kind, Uri? link)
    {
        // Links are bearer secrets: logged only in Development, to make local testing possible.
        if (environment.IsDevelopment() && link is not null)
        {
            LogDevelopment(logger, kind, link);
        }
        else
        {
            LogMissing(logger, kind);
        }

        return Task.CompletedTask;
    }

    [LoggerMessage(EventId = 6401, Level = LogLevel.Information, Message = "Development: {Kind} email link {Link}")]
    private static partial void LogDevelopment(ILogger logger, string kind, Uri link);

    [LoggerMessage(EventId = 6402, Level = LogLevel.Warning, Message = "A {Kind} email was not sent: register an IAccountEmailSender.")]
    private static partial void LogMissing(ILogger logger, string kind);
}

internal sealed partial class LoggingNotifier(ILogger<LoggingNotifier> logger) : INotifier
{
    public Task NotifyAsync(UserNotification notification, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(notification);
        Log(logger, notification.Kind, notification.UserId);
        return Task.CompletedTask;
    }

    [LoggerMessage(EventId = 6411, Level = LogLevel.Warning, Message = "Notification {Kind} for user {UserId} has no delivery channel; register an INotifier.")]
    private static partial void Log(ILogger logger, string kind, Guid userId);
}

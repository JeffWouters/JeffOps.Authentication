using System.Security.Cryptography;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Features.Accounts;
using JeffOps.Authentication.Infrastructure.Persistence;
using JeffOps.Authentication.SharedKernel.Handlers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// What the token server's own tables keep about an account, besides the account and its logins: personal access tokens,
/// session records, providers' refresh tokens, and its OpenIddict tokens and authorizations. Those are deleted, not only
/// revoked: their payloads hold the account's claims (email, name).
/// </summary>
internal sealed class TokenServerAccountData(
    AuthenticationDbContext db,
    IOpenIddictTokenManager tokens,
    IOpenIddictAuthorizationManager authorizations) : IAccountDataEraser
{
    public Task<AccountDeletionBlocker?> BlockerAsync(Guid accountId, CancellationToken cancellationToken) =>
        Task.FromResult<AccountDeletionBlocker?>(null);

    public async Task EraseAsync(Guid accountId, CancellationToken cancellationToken)
    {
        await db.PersonalAccessTokens.Where(token => token.AccountId == accountId).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        await db.EndedSessions.Where(session => session.AccountId == accountId).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        await db.ExternalSessions.Where(session => session.AccountId == accountId).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);
        await db.ProviderSessions.Where(session => session.AccountId == accountId).ExecuteDeleteAsync(cancellationToken).ConfigureAwait(false);

        // Read first, then delete: one query at a time on the context.
        var subject = accountId.ToString();
        var found = new List<object>();
        await foreach (var token in tokens.FindBySubjectAsync(subject, cancellationToken).ConfigureAwait(false))
        {
            found.Add(token);
        }

        foreach (var token in found)
        {
            await tokens.DeleteAsync(token, cancellationToken).ConfigureAwait(false);
        }

        found.Clear();
        await foreach (var authorization in authorizations.FindBySubjectAsync(subject, cancellationToken).ConfigureAwait(false))
        {
            found.Add(authorization);
        }

        foreach (var authorization in found)
        {
            await authorizations.DeleteAsync(authorization, cancellationToken).ConfigureAwait(false);
        }
    }
}

/// <summary>
/// Deletes inactive accounts when the host turns it on (<see cref="TokenServerOptions.InactiveAccounts"/>): every
/// <see cref="InactiveAccountOptions.CheckInterval"/>, after a random first delay, one pass of
/// <see cref="DeleteInactiveAccountsCommand"/>. Every instance runs it; a deletion another instance already made is skipped.
/// </summary>
internal sealed partial class InactiveAccountMaintenance(
    IServiceScopeFactory scopes,
    IOptions<TokenServerOptions> options,
    TimeProvider time,
    ILogger<InactiveAccountMaintenance> logger) : BackgroundService
{
    private static readonly TimeSpan FirstDelay = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = options.Value.InactiveAccounts;
        if (settings.DeleteAfter is null)
        {
            return;
        }

        await Task.Delay(TimeSpan.FromMilliseconds(RandomNumberGenerator.GetInt32((int)FirstDelay.TotalMilliseconds + 1)), time, stoppingToken).ConfigureAwait(false);
        while (!stoppingToken.IsCancellationRequested)
        {
            await RunAsync(stoppingToken).ConfigureAwait(false);
            await Task.Delay(settings.CheckInterval, time, stoppingToken).ConfigureAwait(false);
        }
    }

    /// <summary>One pass. A failed pass is logged and tried again at the next interval.</summary>
    internal async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            var result = await scope.ServiceProvider.GetRequiredService<ICommandHandler<DeleteInactiveAccountsCommand, InactiveAccountsResult>>()
                .HandleAsync(new DeleteInactiveAccountsCommand(), cancellationToken).ConfigureAwait(false);
            if (result.IsSuccess && result.Value.Warned + result.Value.Deleted + result.Value.Kept > 0)
            {
                LogPass(logger, result.Value.Warned, result.Value.Deleted, result.Value.Kept);
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

    [LoggerMessage(EventId = 8841, Level = LogLevel.Information, Message = "Inactive accounts: warned {Warned}, deleted {Deleted}, kept {Kept} that can't be deleted now.")]
    private static partial void LogPass(ILogger logger, int warned, int deleted, int kept);

    [LoggerMessage(EventId = 8842, Level = LogLevel.Error, Message = "Looking for inactive accounts failed; retrying at the next interval.")]
    private static partial void LogFailed(ILogger logger, Exception exception);
}

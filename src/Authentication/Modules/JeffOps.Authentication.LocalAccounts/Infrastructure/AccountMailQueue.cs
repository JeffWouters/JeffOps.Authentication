using System.Threading.Channels;
using JeffOps.Authentication.LocalAccounts.Application;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace JeffOps.Authentication.LocalAccounts.Infrastructure;

/// <summary>The account emails waiting to be sent, in memory (per instance). When it is full, a new email is dropped and logged.</summary>
internal sealed partial class AccountMailQueue(ILogger<AccountMailQueue> logger) : IAccountMailQueue
{
    private const int Capacity = 10_000;

    private readonly Channel<Func<IAccountEmailSender, CancellationToken, Task>> _channel =
        Channel.CreateBounded<Func<IAccountEmailSender, CancellationToken, Task>>(new BoundedChannelOptions(Capacity) { SingleReader = true });

    public ChannelReader<Func<IAccountEmailSender, CancellationToken, Task>> Reader => _channel.Reader;

    public void Enqueue(Func<IAccountEmailSender, CancellationToken, Task> send)
    {
        ArgumentNullException.ThrowIfNull(send);
        if (!_channel.Writer.TryWrite(send))
        {
            LogFull(logger, Capacity);
        }
    }

    [LoggerMessage(EventId = 6421, Level = LogLevel.Warning, Message = "The account email queue is full ({Capacity}); an email was dropped.")]
    private static partial void LogFull(ILogger logger, int capacity);
}

/// <summary>Sends the queued account emails, each with a sender from a scope of its own. Emails queued before shutdown still go out.</summary>
internal sealed partial class AccountMailWorker(AccountMailQueue queue, IServiceScopeFactory scopes, ILogger<AccountMailWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await foreach (var send in queue.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
            {
                await SendAsync(send, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }

        while (queue.Reader.TryRead(out var send))
        {
            await SendAsync(send, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task SendAsync(Func<IAccountEmailSender, CancellationToken, Task> send, CancellationToken cancellationToken)
    {
        try
        {
            await using var scope = scopes.CreateAsyncScope();
            await send(scope.ServiceProvider.GetRequiredService<IAccountEmailSender>(), cancellationToken).ConfigureAwait(false);
        }
#pragma warning disable CA1031 // One failed email must not stop the others; the sender's failure is logged.
        catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
        {
            LogFailed(logger, exception);
        }
    }

    [LoggerMessage(EventId = 6422, Level = LogLevel.Error, Message = "An account email could not be sent.")]
    private static partial void LogFailed(ILogger logger, Exception exception);
}

using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Contracts;
using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.Abstractions.Notifications;
using JeffOps.Authentication.Application.Features.Accounts;
using JeffOps.Authentication.SharedKernel.Handlers;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace JeffOps.Authentication.Server.Tests;

public sealed class AccountDeletionTests
{
    [Fact]
    public async Task A_user_deletes_their_own_account_and_its_tokens_and_pats_go_with_it()
    {
        var events = new ConcurrentQueue<AccountDeletedEvent>();
        await using var server = await TokenServerHost.StartAsync(configure: builder =>
            builder.Services.AddSingleton<IIntegrationEventHandler<AccountDeletedEvent>>(new Recorder(events)));
        var account = await server.CreateAccountAsync("leaving@example.com");
        var tokens = await server.SignInAsync(account.Id);
        var pat = await server.SendAsync(HttpMethod.Post, "account/pats", tokens.AccessToken, JsonContent.Create(new CreatePersonalAccessTokenRequest("ci", 7, ["reports.read"])));
        var secret = (await pat.Content.ReadFromJsonAsync<CreatePersonalAccessTokenResponse>(TestContext.Current.CancellationToken))!.Secret;

        var deleted = await server.SendAsync(HttpMethod.Delete, "account", tokens.AccessToken);

        deleted.StatusCode.ShouldBe(HttpStatusCode.NoContent, await deleted.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        (await server.FindAccountAsync("leaving@example.com")).ShouldBeNull();
        (await server.RefreshAsync(tokens.RefreshToken!)).Error.ShouldBe("invalid_grant");
        (await server.ExchangePatAsync(secret)).Error.ShouldBe("invalid_grant");
        (await StoredTokensAsync(server, account.Id)).ShouldBe(0, "its tokens are deleted, not only revoked: their payloads hold its claims");
        events.Select(deletion => (deletion.AccountId, deletion.Reason)).ShouldBe([(account.Id, AccountDeletionReasons.Requested)]);
    }

    [Fact]
    public async Task Deleting_an_account_needs_a_recent_multi_factor_sign_in()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var tokens = await server.SignInAsync(account.Id, multiFactor: false);

        var refused = await server.SendAsync(HttpMethod.Delete, "account", tokens.AccessToken);

        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await CodeAsync(refused)).ShouldBe("step_up_required");
        (await server.FindAccountAsync(account.Email)).ShouldNotBeNull();
    }

    [Fact]
    public async Task Only_an_operator_deletes_someone_else_s_account()
    {
        await using var server = await TokenServerHost.StartAsync();
        var user = await server.CreateAccountAsync("user@example.com");
        var other = await server.CreateAccountAsync("other@example.com");
        var otherTokens = await server.SignInAsync(other.Id);

        // Without the administration permission, the route is forbidden.
        (await server.SendAsync(HttpMethod.Delete, $"admin/accounts/{user.Id}", otherTokens.AccessToken)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        // An operator (permission decided by the host) deletes it.
        await using var scope = server.Services.CreateAsyncScope();
        var result = await scope.ServiceProvider.GetRequiredService<ICommandHandler<DeleteAccountCommand>>()
            .HandleAsync(new DeleteAccountCommand(other.Id, user.Id, AccountDeletionReasons.Operator), TestContext.Current.CancellationToken);
        result.IsSuccess.ShouldBeTrue();
        (await server.FindAccountAsync("user@example.com")).ShouldBeNull();
    }

    [Fact]
    public async Task Inactive_accounts_are_warned_then_deleted_and_signing_in_keeps_them()
    {
        var notifications = new ConcurrentQueue<UserNotification>();
        await using var server = await TokenServerHost.StartAsync(
            new() { ["JeffOps:TokenServer:InactiveAccounts:DeleteAfter"] = "395.00:00:00" },
            configure: builder =>
            {
                builder.Services.AddSingleton<INotifier>(new NotificationRecorder(notifications));

                // Passes run here, one at a time, not on the background timer that advancing the clock would fire.
                builder.Services.Remove(builder.Services.Single(service => service.ImplementationType == typeof(Infrastructure.Server.InactiveAccountMaintenance)));
            });
        var idle = await server.CreateAccountAsync("idle@example.com");
        var returning = await server.CreateAccountAsync("returning@example.com");

        // Inactive for 13 months less the 30 days' notice: both users are told.
        server.Time.Advance(TimeSpan.FromDays(366));
        (await SweepAsync(server)).ShouldBe(new InactiveAccountsResult(2, 0, 0));
        notifications.Select(notification => (notification.UserId, notification.Kind)).ShouldBe(
            [(idle.Id, "account.deletion_scheduled"), (returning.Id, "account.deletion_scheduled")], ignoreOrder: true);

        // One signs in: that cancels it. A pass meanwhile tells no one again.
        await server.SignInAsync(returning.Id);
        server.Time.Advance(TimeSpan.FromDays(29));
        (await SweepAsync(server)).ShouldBe(new InactiveAccountsResult(0, 0, 0));

        // The notice is over: the account still unused goes.
        server.Time.Advance(TimeSpan.FromDays(2));
        (await SweepAsync(server)).ShouldBe(new InactiveAccountsResult(0, 1, 0));
        (await server.FindAccountAsync("idle@example.com")).ShouldBeNull();
        (await server.FindAccountAsync("returning@example.com")).ShouldNotBeNull();
    }

    [Fact]
    public async Task An_inactive_account_that_can_t_be_deleted_is_kept_without_telling_its_user_and_queued_behind_the_others()
    {
        var notifications = new ConcurrentQueue<UserNotification>();
        var blocked = new HashSet<Guid>();
        await using var server = await TokenServerHost.StartAsync(
            new() { ["JeffOps:TokenServer:InactiveAccounts:DeleteAfter"] = "395.00:00:00" },
            configure: builder =>
            {
                builder.Services.AddSingleton<INotifier>(new NotificationRecorder(notifications));
                builder.Services.AddScoped<Application.Abstractions.IAccountDataEraser>(_ => new Blocking(blocked));
                builder.Services.Remove(builder.Services.Single(service => service.ImplementationType == typeof(Infrastructure.Server.InactiveAccountMaintenance)));
            });
        var managed = await server.CreateAccountAsync("managed@example.com");
        blocked.Add(managed.Id);

        server.Time.Advance(TimeSpan.FromDays(366));
        (await SweepAsync(server)).ShouldBe(new InactiveAccountsResult(0, 0, 0));
        notifications.ShouldBeEmpty("its deletion won't happen");

        server.Time.Advance(TimeSpan.FromDays(31));
        (await SweepAsync(server)).ShouldBe(new InactiveAccountsResult(0, 0, 1));
        (await server.FindAccountAsync("managed@example.com"))!.DeletionWarnedAt.ShouldBe(DateTimeOffset.FromUnixTimeMilliseconds(server.Time.GetUtcNow().ToUnixTimeMilliseconds()), "queued again, behind the others");

        // Once it can be deleted, it goes a notice period later.
        blocked.Clear();
        server.Time.Advance(TimeSpan.FromDays(31));
        (await SweepAsync(server)).ShouldBe(new InactiveAccountsResult(0, 1, 0));
    }

    [Theory]
    [InlineData("30.00:00:00")]
    [InlineData("10.00:00:00")]
    public async Task Inactive_accounts_are_deleted_only_after_their_notice(string deleteAfter) =>
        (await Should.ThrowAsync<Microsoft.Extensions.Options.OptionsValidationException>(() => TokenServerHost.StartAsync(new()
        {
            ["JeffOps:TokenServer:InactiveAccounts:DeleteAfter"] = deleteAfter,
        }))).Message.ShouldContain("InactiveAccounts");

    private static async Task<InactiveAccountsResult> SweepAsync(TokenServerHost server)
    {
        await using var scope = server.Services.CreateAsyncScope();
        var result = await scope.ServiceProvider.GetRequiredService<ICommandHandler<DeleteInactiveAccountsCommand, InactiveAccountsResult>>()
            .HandleAsync(new DeleteInactiveAccountsCommand(), TestContext.Current.CancellationToken);
        return result.Value;
    }

    private static async Task<int> StoredTokensAsync(TokenServerHost server, Guid accountId)
    {
        await using var scope = server.Services.CreateAsyncScope();
        var count = 0;
        await foreach (var _ in scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>().FindBySubjectAsync(accountId.ToString(), TestContext.Current.CancellationToken))
        {
            count++;
        }

        return count;
    }

    private static async Task<string?> CodeAsync(HttpResponseMessage response)
    {
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return body.RootElement.TryGetProperty("code", out var code) ? code.GetString() : null;
    }

    private sealed class Recorder(ConcurrentQueue<AccountDeletedEvent> events) : IIntegrationEventHandler<AccountDeletedEvent>
    {
        public Task HandleAsync(AccountDeletedEvent integrationEvent, CancellationToken cancellationToken)
        {
            events.Enqueue(integrationEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class Blocking(HashSet<Guid> blocked) : Application.Abstractions.IAccountDataEraser
    {
        public Task<Application.Abstractions.AccountDeletionBlocker?> BlockerAsync(Guid accountId, CancellationToken cancellationToken) =>
            Task.FromResult(blocked.Contains(accountId) ? new Application.Abstractions.AccountDeletionBlocker("managed_by_organization", "Managed.") : null);

        public Task EraseAsync(Guid accountId, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class NotificationRecorder(ConcurrentQueue<UserNotification> notifications) : INotifier
    {
        public Task NotifyAsync(UserNotification notification, CancellationToken cancellationToken)
        {
            notifications.Enqueue(notification);
            return Task.CompletedTask;
        }
    }
}

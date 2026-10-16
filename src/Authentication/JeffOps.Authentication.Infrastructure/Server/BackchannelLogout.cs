using System.Security.Claims;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.SharedKernel.Domain;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// When an operator disables an account, or its sessions are revoked (credentials changed, "sign out everywhere"), its
/// sessions end everywhere at once instead of at their next refresh: every token
/// of the account is revoked here, and every client with a back-channel logout URI receives a signed
/// <c>logout_token</c> (OpenID Connect Back-Channel Logout 1.0) so it can drop its server-side sessions too.
/// </summary>
internal sealed partial class BackchannelLogoutNotifier(
    IOpenIddictTokenManager tokens,
    ITokenKeyProvider keys,
    IHttpClientFactory httpClientFactory,
    IOptions<TokenServerOptions> options,
    TimeProvider time,
    ILogger<BackchannelLogoutNotifier> logger) : IDomainEventHandler<AccountStatusChanged>, IDomainEventHandler<AccountSessionsRevoked>, ISessionLogoutNotifier
{
    public const string HttpClientName = "JeffOps.BackchannelLogout";
    private const string BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout";

    public async Task HandleAsync(AccountStatusChanged domainEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);
        if (!domainEvent.Disabled)
        {
            return;
        }

        await EndSessionsAsync(domainEvent.AccountId, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Signing out everywhere (a password change, a user's or operator's request) ends sessions the same way.</summary>
    public Task HandleAsync(AccountSessionsRevoked domainEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);
        return EndSessionsAsync(domainEvent.AccountId, cancellationToken);
    }

    /// <summary>
    /// One session ended (the user signed out here): clients drop that session. Its refresh tokens are refused by the
    /// refresh grant; the account's other sessions continue.
    /// </summary>
    public async Task SessionEndedAsync(Guid accountId, string sessionId, CancellationToken cancellationToken)
    {
        foreach (var client in options.Value.Clients.Where(client => client.BackchannelLogoutUri is not null))
        {
            await NotifyAsync(client, accountId.ToString(), sessionId, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task EndSessionsAsync(Guid accountId, CancellationToken cancellationToken)
    {
        var subject = accountId.ToString();
        await tokens.RevokeBySubjectAsync(subject, cancellationToken).ConfigureAwait(false);

        foreach (var client in options.Value.Clients.Where(client => client.BackchannelLogoutUri is not null))
        {
            await NotifyAsync(client, subject, sessionId: null, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task NotifyAsync(ClientDefinition client, string subject, string? sessionId, CancellationToken cancellationToken)
    {
        try
        {
            using var content = new FormUrlEncodedContent(new Dictionary<string, string> { ["logout_token"] = CreateLogoutToken(client.ClientId, subject, sessionId) });
            using var response = await httpClientFactory.CreateClient(HttpClientName)
                .PostAsync(client.BackchannelLogoutUri, content, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                LogRefused(logger, client.ClientId, (int)response.StatusCode);
            }
        }
#pragma warning disable CA1031 // One unreachable client must not stop the others; its tokens are revoked regardless.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogFailed(logger, exception, client.ClientId);
        }
    }

    internal string CreateLogoutToken(string audience, string subject, string? sessionId = null)
    {
        var now = time.GetUtcNow();
        var signingKeys = keys.GetSigningKeys();
        var signer = signingKeys.FirstOrDefault(key => key.ActivatesAt <= now) ?? signingKeys[^1];

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = options.Value.Issuer?.AbsoluteUri,
            Audience = audience,
            IssuedAt = now.UtcDateTime,
            Subject = new ClaimsIdentity(
                sessionId is null
                    ? [new Claim("sub", subject), new Claim("jti", Guid.NewGuid().ToString("N"))]
                    : [new Claim("sub", subject), new Claim("sid", sessionId), new Claim("jti", Guid.NewGuid().ToString("N"))]),
            Claims = new Dictionary<string, object> { ["events"] = new Dictionary<string, object> { [BackchannelLogoutEvent] = new Dictionary<string, object>() } },
            TokenType = "logout+jwt",
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(signer.Key) { KeyId = signer.KeyId }, SecurityAlgorithms.RsaSha256),
        });
    }

    [LoggerMessage(EventId = 8501, Level = LogLevel.Warning, Message = "Client {ClientId} refused a back-channel logout ({Status}).")]
    private static partial void LogRefused(ILogger logger, string clientId, int status);

    [LoggerMessage(EventId = 8502, Level = LogLevel.Warning, Message = "Sending a back-channel logout to client {ClientId} failed.")]
    private static partial void LogFailed(ILogger logger, Exception exception, string clientId);
}

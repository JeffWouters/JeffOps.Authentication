using System.Security.Cryptography;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Infrastructure.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using static OpenIddict.Client.OpenIddictClientModels;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>A session here whose provider is re-checked, with the provider's refresh token (protected with Data Protection).</summary>
public sealed class ProviderSessionEntry
{
    /// <summary>Keeps <paramref name="provider"/>'s protected refresh token for the session <paramref name="sessionId"/>.</summary>
    public ProviderSessionEntry(string sessionId, string provider, Guid accountId, string protectedRefreshToken, long checkedAtUnixMs, long expiresAtUnixMs)
    {
        SessionId = sessionId;
        Provider = provider;
        AccountId = accountId;
        ProtectedRefreshToken = protectedRefreshToken;
        CheckedAtUnixMs = checkedAtUnixMs;
        ExpiresAtUnixMs = expiresAtUnixMs;
    }

    private ProviderSessionEntry()
    {
    }

    /// <summary>The session here (<c>sid</c>).</summary>
    public string SessionId { get; private set; } = string.Empty;

    /// <summary>The provider's name.</summary>
    public string Provider { get; private set; } = string.Empty;

    /// <summary>Whose session it is.</summary>
    public Guid AccountId { get; private set; }

    /// <summary>The provider's refresh token, protected with Data Protection.</summary>
    public string ProtectedRefreshToken { get; private set; } = string.Empty;

    /// <summary>When the provider last accepted the session (or the sign-in), in Unix milliseconds.</summary>
    public long CheckedAtUnixMs { get; private set; }

    /// <summary>When the session here can no longer be alive, in Unix milliseconds.</summary>
    public long ExpiresAtUnixMs { get; private set; }

    internal void Accepted(string protectedRefreshToken, long nowUnixMs)
    {
        ProtectedRefreshToken = protectedRefreshToken;
        CheckedAtUnixMs = nowUnixMs;
    }
}

/// <summary>
/// Provider sessions in the token server's database, checked by redeeming the provider's refresh token through the OpenIddict
/// client. Expired entries, and those of ended sessions, are deleted by <see cref="StoreMaintenance"/>.
/// </summary>
internal sealed partial class DatabaseProviderSessionChecks(
    AuthenticationDbContext db,
    IDataProtectionProvider dataProtection,
    IEnumerable<IExternalIdentityMapper> mappers,
    IServiceProvider services,
    TimeProvider time,
    ILogger<DatabaseProviderSessionChecks> logger) : IProviderSessionChecks
{
    private const string Purpose = "JeffOps.Authentication.ProviderSessions.RefreshToken";

    /// <summary>How long a check may hold up the grant it is part of; a slower provider counts as unreachable.</summary>
    private static readonly TimeSpan CheckTimeout = TimeSpan.FromSeconds(10);

    private IDataProtector Protector => dataProtection.CreateProtector(Purpose);

    public async Task KeepAsync(string provider, string sessionId, Guid accountId, string refreshToken, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(provider);
        ArgumentException.ThrowIfNullOrEmpty(sessionId);
        ArgumentException.ThrowIfNullOrEmpty(refreshToken);
        db.ProviderSessions.Add(new ProviderSessionEntry(
            sessionId, provider, accountId, Protector.Protect(refreshToken), time.GetUtcNow().ToUnixTimeMilliseconds(), expiresAt.ToUnixTimeMilliseconds()));
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> StandsAsync(string sessionId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(sessionId);
        var now = time.GetUtcNow();
        var nowMs = now.ToUnixTimeMilliseconds();
        var entry = await db.ProviderSessions.FirstOrDefaultAsync(session => session.SessionId == sessionId && session.ExpiresAtUnixMs > nowMs, cancellationToken)
            .ConfigureAwait(false);

        // Not a checked session, a provider no longer checked, or checked recently enough.
        if (entry is null
            || IntervalOf(entry.Provider) is not { } interval
            || now - DateTimeOffset.FromUnixTimeMilliseconds(entry.CheckedAtUnixMs) < interval)
        {
            return true;
        }

        string refreshToken;
        try
        {
            refreshToken = Protector.Unprotect(entry.ProtectedRefreshToken);
        }
        catch (CryptographicException exception)
        {
            // The key ring no longer reads it, so the session can't be checked any more: it ends, and the user signs in again.
            LogUnreadable(logger, entry.Provider, exception);
            return false;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(CheckTimeout);
        try
        {
            var result = await services.GetRequiredService<OpenIddictClientService>().AuthenticateWithRefreshTokenAsync(new RefreshTokenAuthenticationRequest
            {
                ProviderName = entry.Provider,
                RefreshToken = refreshToken,
                DisableUserInfo = true,
                CancellationToken = timeout.Token,
            }).ConfigureAwait(false);

            // Providers that rotate refresh tokens (Entra does) return a new one; keep it.
            entry.Accepted(result.RefreshToken is { Length: > 0 } rotated ? Protector.Protect(rotated) : entry.ProtectedRefreshToken, nowMs);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (OpenIddictExceptions.ProtocolException exception) when (IsRefusal(exception))
        {
            LogRefused(logger, entry.Provider, exception.Error);
            db.ProviderSessions.Remove(entry);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return false;
        }
#pragma warning disable CA1031 // Anything else (unreachable, too slow, a server error, this server's own client refused) is no verdict on the user.
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
        {
            LogUnavailable(logger, entry.Provider, exception);
            return true;
        }
    }

    /// <summary>
    /// The provider's answers about the user: the grant is no longer valid (user disabled or deleted, sessions or consent revoked)
    /// or the user must interact again (a Conditional Access condition, sign-in frequency, MFA). <c>invalid_client</c> and
    /// <c>unauthorized_client</c> are about this server (an expired secret): an outage, not the user's verdict.
    /// </summary>
    private static bool IsRefusal(OpenIddictExceptions.ProtocolException exception) =>
        exception.Error is Errors.InvalidGrant or Errors.InteractionRequired or Errors.LoginRequired or Errors.ConsentRequired;

    private TimeSpan? IntervalOf(string provider) =>
        mappers.SelectMany(mapper => mapper.Providers).FirstOrDefault(known => string.Equals(known.Name, provider, StringComparison.Ordinal))?.SessionCheckInterval;

    [LoggerMessage(EventId = 8831, Level = LogLevel.Information, Message = "Provider {Provider} refused a session's refresh token ({Error}); the session ends.")]
    private static partial void LogRefused(ILogger logger, string provider, string? error);

    [LoggerMessage(EventId = 8832, Level = LogLevel.Warning, Message = "Checking a session with provider {Provider} failed; the session continues and is checked again at its next refresh.")]
    private static partial void LogUnavailable(ILogger logger, string provider, Exception exception);

    [LoggerMessage(EventId = 8833, Level = LogLevel.Warning, Message = "A session's refresh token for provider {Provider} can no longer be read; the session ends.")]
    private static partial void LogUnreadable(ILogger logger, string provider, Exception exception);
}

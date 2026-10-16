using System.Security.Cryptography;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Domain.Keys;
using JeffOps.Authentication.Infrastructure.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Infrastructure.Keys;

/// <summary>Signing-key settings. Bound from <c>JeffOps:TokenServer:SigningKeys</c>.</summary>
public sealed class SigningKeyOptions
{
    /// <summary>The configuration section the options bind from.</summary>
    public const string SectionName = "JeffOps:TokenServer:SigningKeys";

    /// <summary>The size in bits of newly created RSA keys. Default: 2048.</summary>
    public int RsaKeySize { get; set; } = 2048;

    /// <summary>Rotate database signing keys. On by default.</summary>
    public bool RotationEnabled { get; set; } = true;

    /// <summary>How old the signing key may get before a successor is created. Default: 30 days.</summary>
    public TimeSpan RotationInterval { get; set; } = TimeSpan.FromDays(30);

    /// <summary>How long a replaced key stays published after it stopped signing; must exceed the longest token lifetime.</summary>
    public TimeSpan Overlap { get; set; } = TimeSpan.FromDays(7);

    /// <summary>How long a new key is published before it signs, so resource services have fetched it.</summary>
    public TimeSpan ActivationDelay { get; set; } = TimeSpan.FromDays(1);

    /// <summary>How often the rotation service checks whether a key is due for creation, retirement or activation. Default: 1 hour.</summary>
    public TimeSpan CheckInterval { get; set; } = TimeSpan.FromHours(1);
}

/// <summary>
/// Token keys kept in the database, private keys protected with Data Protection. Signing keys rotate
/// (<see cref="KeyRotationService"/>); the encryption key (for refresh tokens and codes) is created once. Loads lazily and
/// creates the first keys itself, so a fresh database works without setup.
/// </summary>
public sealed partial class DatabaseKeyStore(
    IServiceScopeFactory scopes,
    IDataProtectionProvider dataProtection,
    IOptions<SigningKeyOptions> options,
    TimeProvider time,
    ILogger<DatabaseKeyStore> logger) : ITokenKeyProvider
{
    private const string Purpose = "JeffOps.Authentication.TokenKeys";

    private readonly IDataProtector _protector = dataProtection.CreateProtector(Purpose);
    private readonly Lock _gate = new();
    private IReadOnlyList<SigningKey>? _signing;
    private IReadOnlyList<RSA>? _encryption;
    private string? _announcedSigner;

    /// <inheritdoc />
    public event EventHandler? KeysChanged;

    /// <inheritdoc />
    public IReadOnlyList<SigningKey> GetSigningKeys()
    {
        EnsureLoaded();
        return _signing!;
    }

    /// <summary>
    /// The keys that encrypt the tokens the server reads back itself (refresh tokens and codes), newest first. Created on
    /// first use and not rotated.
    /// </summary>
    public IReadOnlyList<RSA> GetEncryptionKeys()
    {
        EnsureLoaded();
        return _encryption!;
    }

    /// <summary>Re-reads the keys and notifies listeners. Called after rotation creates or retires a key.</summary>
    public void Reload()
    {
        lock (_gate)
        {
            _signing = null;
            _encryption = null;
        }

        EnsureLoaded();
        KeysChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Notifies listeners when the key that should sign now differs from the one last announced: a pending key's activation
    /// time has passed. Nothing in storage changes then, so only the clock can tell.
    /// </summary>
    public void NotifyIfSignerChanged()
    {
        var signer = CurrentSigner(GetSigningKeys(), time.GetUtcNow());
        if (signer == Volatile.Read(ref _announcedSigner))
        {
            return;
        }

        Volatile.Write(ref _announcedSigner, signer);
        KeysChanged?.Invoke(this, EventArgs.Empty);
    }

    private static string? CurrentSigner(IReadOnlyList<SigningKey> newestFirst, DateTimeOffset now) =>
        (newestFirst.FirstOrDefault(key => key.ActivatesAt <= now) ?? newestFirst.LastOrDefault())?.KeyId;

    internal StoredKey CreateKey(KeyUse use, DateTimeOffset now, TimeSpan activationDelay)
    {
        using var rsa = RSA.Create(options.Value.RsaKeySize);
        return StoredKey.Create(use, _protector.Protect(Convert.ToBase64String(rsa.ExportPkcs8PrivateKey())), now, activationDelay);
    }

    private void EnsureLoaded()
    {
        if (_signing is not null && _encryption is not null)
        {
            return;
        }

        lock (_gate)
        {
            if (_signing is not null && _encryption is not null)
            {
                return;
            }

            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>();
            var stored = db.StoredKeys.Where(key => key.RetiredAt == null).ToList();
            var now = time.GetUtcNow();

            var signing = LoadOrCreate(db, stored, KeyUse.Signing, now);
            var encryption = LoadOrCreate(db, stored, KeyUse.Encryption, now);
            db.SaveChanges();

            _signing = [.. signing.OrderByDescending(pair => pair.Stored.CreatedAt)
                .Select(pair => new SigningKey(pair.Stored.KeyId, pair.Key, pair.Stored.ActivatesAt))];
            _encryption = [.. encryption.OrderByDescending(pair => pair.Stored.CreatedAt).Select(pair => pair.Key)];
            Volatile.Write(ref _announcedSigner, CurrentSigner(_signing, now));
        }
    }

    private List<(StoredKey Stored, RSA Key)> LoadOrCreate(AuthenticationDbContext db, List<StoredKey> stored, KeyUse use, DateTimeOffset now)
    {
        var keys = new List<(StoredKey, RSA)>();
        foreach (var record in stored.Where(key => key.Use == use))
        {
            try
            {
                var rsa = RSA.Create();
                rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(_protector.Unprotect(record.ProtectedPrivateKey)), out _);
                keys.Add((record, rsa));
            }
            catch (Exception exception) when (exception is CryptographicException or FormatException)
            {
                // The Data Protection key ring that protected it is gone: the key is unusable, retire it.
                LogUnreadableKey(logger, exception, record.KeyId);
                record.Retire(now);
            }
        }

        if (keys.Count == 0)
        {
            // The first key of a store signs immediately: nothing has been published before it.
            var record = CreateKey(use, now, TimeSpan.Zero);
            db.StoredKeys.Add(record);
            var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(Convert.FromBase64String(_protector.Unprotect(record.ProtectedPrivateKey)), out _);
            keys.Add((record, rsa));
        }

        return keys;
    }

    [LoggerMessage(EventId = 8201, Level = LogLevel.Warning, Message = "Token key {KeyId} can't be decrypted (lost Data Protection key ring?); retiring it.")]
    private static partial void LogUnreadableKey(ILogger logger, Exception exception, string keyId);
}

/// <summary>
/// Rotates database signing keys on schedule and reloads the server's credentials when the set changes or a pending key
/// activates, without a restart (docs/DESIGN.md §17, I4).
/// </summary>
internal sealed partial class KeyRotationService(
    DatabaseKeyStore store,
    IServiceScopeFactory scopes,
    IOptions<SigningKeyOptions> options,
    TimeProvider time,
    ILogger<KeyRotationService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = options.Value;
        if (!settings.RotationEnabled)
        {
            return;
        }

        using var timer = new PeriodicTimer(settings.CheckInterval, time);
        do
        {
            try
            {
                await RotateOnceAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
#pragma warning disable CA1031 // A failed pass is logged and retried at the next tick.
            catch (Exception exception)
#pragma warning restore CA1031
            {
                LogRotationFailed(logger, exception);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }

    internal async Task RotateOnceAsync(CancellationToken cancellationToken)
    {
        var settings = options.Value;
        var now = time.GetUtcNow();

        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>();
        var active = (await db.StoredKeys.Where(key => key.RetiredAt == null).ToListAsync(cancellationToken).ConfigureAwait(false))
            .Where(key => key.Use == KeyUse.Signing)
            .ToList();

        var plan = KeyRotation.Plan(active, now, settings.RotationInterval, settings.Overlap);
        if (plan.CreateNew)
        {
            var created = store.CreateKey(KeyUse.Signing, now, settings.ActivationDelay);
            db.StoredKeys.Add(created);
            LogKeyCreated(logger, created.KeyId, created.ActivatesAt);
        }

        foreach (var retired in plan.ToRetire)
        {
            retired.Retire(now);
            LogKeyRetired(logger, retired.KeyId);
        }

        if (plan.CreateNew || plan.ToRetire.Count > 0)
        {
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            store.Reload();
        }
        else
        {
            store.NotifyIfSignerChanged();
        }
    }

    [LoggerMessage(EventId = 8202, Level = LogLevel.Information, Message = "Created signing key {KeyId}; it is published now and signs from {ActivatesAt:o}.")]
    private static partial void LogKeyCreated(ILogger logger, string keyId, DateTimeOffset activatesAt);

    [LoggerMessage(EventId = 8203, Level = LogLevel.Information, Message = "Retired signing key {KeyId}; every token it signed has expired.")]
    private static partial void LogKeyRetired(ILogger logger, string keyId);

    [LoggerMessage(EventId = 8204, Level = LogLevel.Error, Message = "Signing-key rotation failed; retrying at the next check.")]
    private static partial void LogRotationFailed(ILogger logger, Exception exception);
}

namespace JeffOps.Authentication.Domain.Keys;

public enum KeyUse
{
    Signing = 0,
    Encryption = 1,
}

/// <summary>
/// A token key held by the database key provider. The private key is stored protected (Data Protection), never in clear.
/// A key is published (JWKS) from creation, signs from <see cref="ActivatesAt"/>, and is dropped once retired.
/// </summary>
public sealed class StoredKey
{
    private StoredKey(Guid id, KeyUse use, string protectedPrivateKey, DateTimeOffset createdAt, DateTimeOffset activatesAt)
    {
        Id = id;
        Use = use;
        ProtectedPrivateKey = protectedPrivateKey;
        CreatedAt = createdAt;
        ActivatesAt = activatesAt;
    }

    private StoredKey()
    {
    }

    public Guid Id { get; private set; }

    public KeyUse Use { get; private set; }

    public string ProtectedPrivateKey { get; private set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; private set; }

    /// <summary>
    /// When the key starts signing. Until then it is only published, so resource services have fetched it before the first
    /// token signed with it reaches them.
    /// </summary>
    public DateTimeOffset ActivatesAt { get; private set; }

    public DateTimeOffset? RetiredAt { get; private set; }

    public static StoredKey Create(KeyUse use, string protectedPrivateKey, DateTimeOffset now, TimeSpan activationDelay) =>
        new(Guid.CreateVersion7(now), use, protectedPrivateKey, now, now + (activationDelay > TimeSpan.Zero ? activationDelay : TimeSpan.Zero));

    public void Retire(DateTimeOffset now) => RetiredAt ??= now;

    public string KeyId => Id.ToString("N");
}

/// <summary>What a rotation pass should do.</summary>
/// <param name="CreateNew">Whether to create a new key.</param>
/// <param name="ToRetire">Keys whose tokens have all expired and that may leave the published set.</param>
public sealed record KeyRotationPlan(bool CreateNew, IReadOnlyList<StoredKey> ToRetire);

/// <summary>
/// Signing-key rotation (docs/DESIGN.md §7.5). A new key is created once the newest is <c>interval</c> old. An older key is
/// retired only when it stopped signing more than <c>overlap</c> ago, so every token it signed has expired first.
/// </summary>
public static class KeyRotation
{
    public static KeyRotationPlan Plan(IReadOnlyCollection<StoredKey> activeKeys, DateTimeOffset now, TimeSpan interval, TimeSpan overlap)
    {
        ArgumentNullException.ThrowIfNull(activeKeys);

        var newestFirst = activeKeys.Where(key => key.RetiredAt is null).OrderByDescending(key => key.CreatedAt).ToList();
        var createNew = newestFirst.Count == 0 || now - newestFirst[0].CreatedAt >= interval;

        // A key stops signing when its successor activates; it may leave once that is more than the overlap ago.
        var toRetire = new List<StoredKey>();
        for (var i = 1; i < newestFirst.Count; i++)
        {
            var successorActivated = newestFirst[i - 1].ActivatesAt;
            if (successorActivated <= now && now - successorActivated >= overlap)
            {
                toRetire.Add(newestFirst[i]);
            }
        }

        return new KeyRotationPlan(createNew, toRetire);
    }

    /// <summary>The key that signs now: the newest active one, or the oldest when none has activated yet.</summary>
    public static StoredKey? CurrentSigner(IReadOnlyCollection<StoredKey> keys, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(keys);

        var live = keys.Where(key => key.RetiredAt is null).OrderByDescending(key => key.CreatedAt).ToList();
        return live.FirstOrDefault(key => key.ActivatesAt <= now) ?? live.LastOrDefault();
    }
}

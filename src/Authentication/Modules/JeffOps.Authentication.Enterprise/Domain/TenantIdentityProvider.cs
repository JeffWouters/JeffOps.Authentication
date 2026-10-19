namespace JeffOps.Authentication.Enterprise.Domain;

/// <summary>
/// A SAML identity provider a tenant registered itself. It signs in only that tenant's people: addresses in the tenant's
/// verified domains, through home realm discovery, and its logins are namespaced to it, so it can never act as another
/// tenant's users even when it names the same entity id.
/// </summary>
public sealed class TenantIdentityProvider
{
    /// <summary>The prefix of a tenant provider's name (<c>tenant-{id}</c>), which its sign-in URLs use.</summary>
    public const string NamePrefix = "tenant-";

    private TenantIdentityProvider(Guid tenantId, DateTimeOffset now)
    {
        Id = Guid.NewGuid();
        TenantId = tenantId;
        CreatedAt = now;
    }

    private TenantIdentityProvider()
    {
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    /// <summary>The name the sign-in URLs use: <c>tenant-{id}</c>.</summary>
    public string Name => NamePrefix + Id.ToString("N");

    public string DisplayName { get; private set; } = string.Empty;

    public string EntityId { get; private set; } = string.Empty;

    public string? MetadataUrl { get; private set; }

    public string? SingleSignOnUrl { get; private set; }

    public string? SingleLogoutUrl { get; private set; }

    /// <summary>The provider's signing certificates (base64 DER or PEM), one per line.</summary>
    public string SigningCertificates { get; private set; } = string.Empty;

    /// <summary>Authentication context classes that count as multi-factor, one per line.</summary>
    public string MultiFactorAuthnContexts { get; private set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset UpdatedAt { get; private set; }

    public Guid? UpdatedBy { get; private set; }

    public IReadOnlyList<string> CertificateList => Lines(SigningCertificates);

    public IReadOnlyList<string> MultiFactorAuthnContextList => Lines(MultiFactorAuthnContexts);

    public static TenantIdentityProvider Create(Guid tenantId, DateTimeOffset now) => new(tenantId, now);

    /// <summary>The name of a tenant provider's id, or null when <paramref name="name"/> isn't one.</summary>
    public static Guid? IdOf(string? name) =>
        name is not null && name.StartsWith(NamePrefix, StringComparison.Ordinal) && Guid.TryParseExact(name[NamePrefix.Length..], "N", out var id)
            && string.Equals(name[NamePrefix.Length..], id.ToString("N"), StringComparison.Ordinal) ? id : null;

    public void Set(
        string displayName,
        string entityId,
        string? metadataUrl,
        string? singleSignOnUrl,
        string? singleLogoutUrl,
        IEnumerable<string> signingCertificates,
        IEnumerable<string> multiFactorAuthnContexts,
        Guid by,
        DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        ArgumentException.ThrowIfNullOrWhiteSpace(entityId);
        DisplayName = displayName.Trim();
        EntityId = entityId.Trim();
        MetadataUrl = Clean(metadataUrl);
        SingleSignOnUrl = Clean(singleSignOnUrl);
        SingleLogoutUrl = Clean(singleLogoutUrl);
        SigningCertificates = string.Join('\n', signingCertificates.Select(value => value.Trim()).Where(value => value.Length > 0));
        MultiFactorAuthnContexts = string.Join('\n', multiFactorAuthnContexts.Select(value => value.Trim()).Where(value => value.Length > 0));
        UpdatedBy = by;
        UpdatedAt = now;
    }

    private static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static string[] Lines(string value) => value.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}

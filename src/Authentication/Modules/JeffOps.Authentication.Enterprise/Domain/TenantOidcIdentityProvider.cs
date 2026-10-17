namespace JeffOps.Authentication.Enterprise.Domain;

/// <summary>
/// An OpenID Connect provider a tenant registered itself. Like a tenant SAML provider it signs in only that tenant's people,
/// through home realm discovery of the tenant's verified domains, and its logins are namespaced to it. Its client secret is
/// stored encrypted and is never shown again.
/// </summary>
public sealed class TenantOidcIdentityProvider
{
    /// <summary>The prefix of its name (<c>tenant-oidc-{id}</c>), which its sign-in URLs use.</summary>
    public const string NamePrefix = "tenant-oidc-";

    private TenantOidcIdentityProvider(Guid tenantId, DateTimeOffset now)
    {
        Id = Guid.NewGuid();
        TenantId = tenantId;
        CreatedAt = now;
    }

    private TenantOidcIdentityProvider()
    {
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    /// <summary>The name the sign-in URLs use: <c>tenant-oidc-{id}</c>.</summary>
    public string Name => NamePrefix + Id.ToString("N");

    public string DisplayName { get; private set; } = string.Empty;

    public string Issuer { get; private set; } = string.Empty;

    public string ClientId { get; private set; } = string.Empty;

    /// <summary>The client secret, encrypted (Data Protection); null when the provider issued none.</summary>
    public string? ProtectedClientSecret { get; private set; }

    /// <summary>Scopes to request besides <c>openid</c>, space-separated.</summary>
    public string Scopes { get; private set; } = string.Empty;

    /// <summary>Authentication context values that count as multi-factor, one per line.</summary>
    public string MultiFactorAcrValues { get; private set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset UpdatedAt { get; private set; }

    public Guid? UpdatedBy { get; private set; }

    public IReadOnlyList<string> ScopeList => Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries);

    public IReadOnlyList<string> MultiFactorAcrValueList => MultiFactorAcrValues.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public static TenantOidcIdentityProvider Create(Guid tenantId, DateTimeOffset now) => new(tenantId, now);

    /// <summary>The id in a tenant OIDC provider's name, or null when <paramref name="name"/> isn't one.</summary>
    public static Guid? IdOf(string? name) =>
        name is not null && name.StartsWith(NamePrefix, StringComparison.Ordinal) && Guid.TryParseExact(name[NamePrefix.Length..], "N", out var id) ? id : null;

    public void Set(string displayName, string issuer, string clientId, IEnumerable<string> scopes, IEnumerable<string> multiFactorAcrValues, Guid by, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        DisplayName = displayName.Trim();
        Issuer = issuer.Trim();
        ClientId = clientId.Trim();
        Scopes = string.Join(' ', scopes.Select(value => value.Trim()).Where(value => value.Length > 0 && value != "openid").Distinct(StringComparer.Ordinal));
        MultiFactorAcrValues = string.Join('\n', multiFactorAcrValues.Select(value => value.Trim()).Where(value => value.Length > 0));
        UpdatedBy = by;
        UpdatedAt = now;
    }

    /// <summary>Replaces the encrypted client secret; null removes it.</summary>
    public void SetClientSecret(string? protectedSecret, Guid by, DateTimeOffset now)
    {
        ProtectedClientSecret = protectedSecret;
        UpdatedBy = by;
        UpdatedAt = now;
    }
}

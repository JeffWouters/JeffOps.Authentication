using System.Security.Cryptography;
using System.Text;

namespace JeffOps.Authentication.Enterprise.Domain;

/// <summary>
/// A bearer token a tenant gives its identity provider for SCIM provisioning. Only its SHA-256 is stored; the secret is
/// shown once. Scoped to one tenant: everything provisioned with it lands in that tenant. It works until revoked, or until the
/// expiry chosen when it was created.
/// </summary>
public sealed class ScimToken
{
    public const string Prefix = "scim_";

    private ScimToken(Guid tenantId, string name, string hash, DateTimeOffset now, DateTimeOffset? expiresAt)
    {
        Id = Guid.NewGuid();
        TenantId = tenantId;
        Name = name;
        TokenHash = hash;
        CreatedAt = now;
        ExpiresAt = expiresAt;
    }

    private ScimToken()
    {
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    public string Name { get; private set; } = string.Empty;

    public string TokenHash { get; private set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? LastUsedAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; private set; }

    /// <summary>When the token stops working; null for never.</summary>
    public DateTimeOffset? ExpiresAt { get; private set; }

    /// <summary>Not revoked, and not expired at <paramref name="now"/>.</summary>
    public bool IsActiveAt(DateTimeOffset now) => RevokedAt is null && (ExpiresAt is not { } expires || now < expires);

    public static (ScimToken Token, string Secret) Issue(Guid tenantId, string name, DateTimeOffset now, DateTimeOffset? expiresAt = null)
    {
        var secret = Prefix + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        return (new ScimToken(tenantId, string.IsNullOrWhiteSpace(name) ? "SCIM" : name.Trim(), HashOf(secret), now, expiresAt), secret);
    }

    public static string HashOf(string secret) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(secret ?? string.Empty)));

    public void Used(DateTimeOffset now) => LastUsedAt = now;

    public void Revoke(DateTimeOffset now) => RevokedAt ??= now;
}

/// <summary>
/// A user as a tenant's identity provider provisioned them: the SCIM view (userName, externalId, active, names) of an
/// account's membership in the tenant. The SCIM id is the account id.
/// </summary>
public sealed class ScimUser
{
    private ScimUser(Guid tenantId, Guid accountId, bool createdAccount, DateTimeOffset now)
    {
        TenantId = tenantId;
        AccountId = accountId;
        CreatedAccount = createdAccount;
        Created = now;
        LastModified = now;
        Active = true;
    }

    private ScimUser()
    {
    }

    public Guid TenantId { get; private set; }

    public Guid AccountId { get; private set; }

    /// <summary>Whether provisioning created the account (then deprovisioning disables it; otherwise it only leaves the tenant).</summary>
    public bool CreatedAccount { get; private set; }

    public string UserName { get; private set; } = string.Empty;

    /// <summary>
    /// <see cref="UserName"/> lower-cased (invariant): what SCIM's case-insensitive comparisons and the tenant's uniqueness use,
    /// stored so the database can seek it in an index.
    /// </summary>
    public string NormalizedUserName { get; private set; } = string.Empty;

    public string? ExternalId { get; private set; }

    public string? GivenName { get; private set; }

    public string? FamilyName { get; private set; }

    public string? DisplayName { get; private set; }

    public bool Active { get; private set; }

    public DateTimeOffset Created { get; private set; }

    public DateTimeOffset LastModified { get; private set; }

    /// <summary>A version for ETags; changes on every update.</summary>
    public int Version { get; private set; }

    /// <summary>
    /// Whether provisioning disabled the account (<c>active: false</c>). Only then may provisioning enable it again: an account
    /// an operator disabled or locked stays that way.
    /// </summary>
    public bool DisabledAccount { get; private set; }

    public void RecordAccountDisabled(bool disabled) => DisabledAccount = disabled;

    public static ScimUser Provision(Guid tenantId, Guid accountId, bool createdAccount, DateTimeOffset now) => new(tenantId, accountId, createdAccount, now);

    public void Update(string userName, string? externalId, string? givenName, string? familyName, string? displayName, bool active, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        UserName = userName.Trim();
        NormalizedUserName = Normalize(UserName);
        ExternalId = Clean(externalId);
        GivenName = Clean(givenName);
        FamilyName = Clean(familyName);
        DisplayName = Clean(displayName);
        Active = active;
        LastModified = now;
        Version++;
    }

    private static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    /// <summary>How SCIM's case-insensitive names are stored for comparison: trimmed and lower-cased (invariant).</summary>
    public static string Normalize(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return value.Trim().ToLowerInvariant();
    }
}

/// <summary>A group a tenant's identity provider provisioned, with its members (account ids). Role assignments can target it.</summary>
public sealed class ScimGroup
{
    private readonly List<ScimGroupMember> _members = [];

    private ScimGroup(Guid tenantId, DateTimeOffset now)
    {
        Id = Guid.NewGuid();
        TenantId = tenantId;
        Created = now;
        LastModified = now;
    }

    private ScimGroup()
    {
    }

    public Guid Id { get; private set; }

    public Guid TenantId { get; private set; }

    public string DisplayName { get; private set; } = string.Empty;

    /// <summary><see cref="DisplayName"/> lower-cased (invariant), for case-insensitive lookups and the tenant's uniqueness.</summary>
    public string NormalizedDisplayName { get; private set; } = string.Empty;

    public string? ExternalId { get; private set; }

    public DateTimeOffset Created { get; private set; }

    public DateTimeOffset LastModified { get; private set; }

    public int Version { get; private set; }

    public IReadOnlyCollection<ScimGroupMember> Members => _members.AsReadOnly();

    public IReadOnlyList<Guid> MemberIds => [.. _members.Select(member => member.AccountId)];

    public static ScimGroup Create(Guid tenantId, string displayName, string? externalId, DateTimeOffset now)
    {
        var group = new ScimGroup(tenantId, now);
        group.Rename(displayName, externalId, now);
        return group;
    }

    public void Rename(string displayName, string? externalId, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
        DisplayName = displayName.Trim();
        NormalizedDisplayName = ScimUser.Normalize(DisplayName);
        ExternalId = string.IsNullOrWhiteSpace(externalId) ? null : externalId.Trim();
        Touch(now);
    }

    public void AddMembers(IEnumerable<Guid> accountIds, DateTimeOffset now)
    {
        foreach (var id in accountIds.Where(id => _members.All(member => member.AccountId != id)).Distinct())
        {
            _members.Add(new ScimGroupMember(Id, id));
        }

        Touch(now);
    }

    public void RemoveMembers(IEnumerable<Guid> accountIds, DateTimeOffset now)
    {
        var removing = accountIds.ToHashSet();
        _members.RemoveAll(member => removing.Contains(member.AccountId));
        Touch(now);
    }

    /// <summary>Records a change in who of its members counts (a member was deactivated or reactivated).</summary>
    public void MembersChanged(DateTimeOffset now) => Touch(now);

    public void ReplaceMembers(IEnumerable<Guid> accountIds, DateTimeOffset now)
    {
        _members.Clear();
        AddMembers(accountIds, now);
    }

    private void Touch(DateTimeOffset now)
    {
        LastModified = now;
        Version++;
    }
}

public sealed class ScimGroupMember
{
    internal ScimGroupMember(Guid groupId, Guid accountId)
    {
        GroupId = groupId;
        AccountId = accountId;
    }

    private ScimGroupMember()
    {
    }

    public Guid GroupId { get; private set; }

    public Guid AccountId { get; private set; }
}

using System.Security.Cryptography;
using JeffOps.Authentication.SharedKernel.Domain;

namespace JeffOps.Authentication.Tenancy.Domain;

public enum TenantStatus
{
    Active = 0,

    /// <summary>Temporarily closed: no sessions are issued for it, nothing is removed.</summary>
    Suspended = 1,

    /// <summary>Closed for good (kept, so its id is never reused and its history stays readable).</summary>
    Deleted = 2,
}

/// <summary>
/// A customer organization, shared by every product that trusts this token server. Products key their data on its id, the
/// <c>tid</c> claim. Exactly one tenant is the platform tenant: its administrators are the platform operators.
/// </summary>
public sealed class Tenant : AggregateRoot<Guid>
{
    public const int MaxNameLength = 200;

    private Tenant(Guid id, string name, bool isPlatform, Guid? createdBy, DateTimeOffset now)
        : base(id)
    {
        Name = name;
        IsPlatform = isPlatform;
        Status = TenantStatus.Active;
        CreatedBy = createdBy;
        CreatedAt = now;
    }

    private Tenant()
    {
    }

    public string Name { get; private set; } = string.Empty;

    public TenantStatus Status { get; private set; }

    public bool IsPlatform { get; private set; }

    public Guid? CreatedBy { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset? StatusChangedAt { get; private set; }

    /// <summary>Whether sessions may be issued for the tenant.</summary>
    public bool AcceptsSessions => Status == TenantStatus.Active;

    public static Tenant Create(string name, Guid? createdBy, DateTimeOffset now, Guid? id = null) =>
        new(id ?? Guid.NewGuid(), NormalizeName(name) ?? throw new ArgumentException("A tenant needs a name.", nameof(name)), isPlatform: false, createdBy, now);

    public static Tenant CreatePlatform(string name, DateTimeOffset now) =>
        new(Guid.NewGuid(), NormalizeName(name) ?? throw new ArgumentException("The platform tenant needs a name.", nameof(name)), isPlatform: true, createdBy: null, now);

    /// <summary>Trimmed, with inner whitespace collapsed; null when empty or too long.</summary>
    public static string? NormalizeName(string? name)
    {
        var collapsed = string.Join(' ', (name ?? string.Empty).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return collapsed.Length is > 0 and <= MaxNameLength ? collapsed : null;
    }

    public void Rename(string name) =>
        Name = NormalizeName(name) ?? throw new ArgumentException("A tenant needs a name.", nameof(name));

    /// <summary>Changes the status. A deleted tenant stays deleted, and the platform tenant can't be closed.</summary>
    public bool TryChangeStatus(TenantStatus status, DateTimeOffset now)
    {
        if (Status == TenantStatus.Deleted || (IsPlatform && status != TenantStatus.Active))
        {
            return false;
        }

        if (Status != status)
        {
            Status = status;
            StatusChangedAt = now;
        }

        return true;
    }
}

public enum MembershipRole
{
    Member = 0,

    /// <summary>Manages the tenant's members, invitations, linked directories and sign-in settings.</summary>
    Admin = 1,
}

/// <summary>How a membership came about, so a source can only take away what it gave (SCIM removes SCIM memberships only).</summary>
public enum MembershipSource
{
    Operator = 0,
    Signup = 1,
    Invitation = 2,

    /// <summary>The account signed in from an Entra directory linked to the tenant.</summary>
    Directory = 3,

    /// <summary>The account signed in through the tenant's own identity provider.</summary>
    Sso = 4,

    /// <summary>The tenant's identity provider provisioned the account (SCIM).</summary>
    Scim = 5,
}

/// <summary>An account's membership of a tenant. One per (tenant, account).</summary>
public sealed class Membership
{
    private Membership(Guid tenantId, Guid accountId, MembershipRole role, MembershipSource source, Guid? addedBy, DateTimeOffset now)
    {
        TenantId = tenantId;
        AccountId = accountId;
        Role = role;
        Source = source;
        AddedBy = addedBy;
        CreatedAt = now;
    }

    private Membership()
    {
    }

    public Guid TenantId { get; private set; }

    public Guid AccountId { get; private set; }

    public MembershipRole Role { get; private set; }

    public MembershipSource Source { get; private set; }

    public Guid? AddedBy { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public bool IsAdmin => Role == MembershipRole.Admin;

    public static Membership Create(Guid tenantId, Guid accountId, MembershipRole role, MembershipSource source, Guid? addedBy, DateTimeOffset now) =>
        new(tenantId, accountId, role, source, addedBy, now);

    public void ChangeRole(MembershipRole role) => Role = role;

    /// <summary>Raises the role to <paramref name="role"/> when it is higher; never lowers it.</summary>
    public void RaiseTo(MembershipRole role)
    {
        if (role > Role)
        {
            Role = role;
        }
    }
}

/// <summary>
/// An Entra directory (its tenant id) whose people join the tenant when they sign in. A directory belongs to at most one tenant.
/// </summary>
public sealed class DirectoryLink
{
    public const string EntraKind = "entra";

    private DirectoryLink(Guid tenantId, string kind, string directoryId, Guid? linkedBy, DateTimeOffset now)
    {
        TenantId = tenantId;
        Kind = kind;
        DirectoryId = directoryId;
        LinkedBy = linkedBy;
        CreatedAt = now;
    }

    private DirectoryLink()
    {
    }

    public Guid TenantId { get; private set; }

    /// <summary>The directory's family; <see cref="EntraKind"/> for now.</summary>
    public string Kind { get; private set; } = string.Empty;

    /// <summary>The directory's id, lower case (Entra: the directory's tenant id).</summary>
    public string DirectoryId { get; private set; } = string.Empty;

    public Guid? LinkedBy { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public static DirectoryLink Entra(Guid tenantId, Guid directoryId, Guid? linkedBy, DateTimeOffset now) =>
        new(tenantId, EntraKind, NormalizeEntra(directoryId), linkedBy, now);

    public static string NormalizeEntra(Guid directoryId) => directoryId.ToString("D");

    /// <summary>The Entra issuer of the directory's sign-ins, as the Entra provider records logins.</summary>
    public static string EntraIssuer(Guid directoryId) => $"https://login.microsoftonline.com/{NormalizeEntra(directoryId)}/v2.0";
}

/// <summary>
/// A single-use invitation to a tenant. Only the token's SHA-256 is stored; whoever opens the link and signs in becomes the
/// member (matched on the link, never on the email address, which some providers don't verify).
/// </summary>
public sealed class Invitation : AggregateRoot<Guid>
{
    public const int MaxEmailLength = 320;

    private Invitation(Guid tenantId, string? email, MembershipRole role, string tokenHash, Guid createdBy, DateTimeOffset now, DateTimeOffset expiresAt)
        : base(Guid.NewGuid())
    {
        TenantId = tenantId;
        Email = email;
        Role = role;
        TokenHash = tokenHash;
        CreatedBy = createdBy;
        CreatedAt = now;
        ExpiresAt = expiresAt;
    }

    private Invitation()
    {
    }

    public Guid TenantId { get; private set; }

    /// <summary>Who it was meant for, for display and delivery only.</summary>
    public string? Email { get; private set; }

    public MembershipRole Role { get; private set; }

    public string TokenHash { get; private set; } = string.Empty;

    public Guid CreatedBy { get; private set; }

    public DateTimeOffset CreatedAt { get; private set; }

    public DateTimeOffset ExpiresAt { get; private set; }

    public Guid? AcceptedBy { get; private set; }

    public DateTimeOffset? AcceptedAt { get; private set; }

    public DateTimeOffset? RevokedAt { get; private set; }

    /// <summary>A new invitation and its token (256 bits, base64url), which is shown once and never stored.</summary>
    public static (Invitation Invitation, string Token) Create(Guid tenantId, string? email, MembershipRole role, Guid createdBy, DateTimeOffset now, TimeSpan lifetime)
    {
        var token = Base64Url(RandomNumberGenerator.GetBytes(32));
        var trimmed = string.IsNullOrWhiteSpace(email) ? null : email.Trim();
        if (trimmed is { Length: > MaxEmailLength })
        {
            throw new ArgumentException("The email address is too long.", nameof(email));
        }

        return (new Invitation(tenantId, trimmed, role, Hash(token), createdBy, now, now + lifetime), token);
    }

    public static string Hash(string token) =>
        Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)));

    public bool IsOpen(DateTimeOffset now) => AcceptedAt is null && RevokedAt is null && now < ExpiresAt;

    public string State(DateTimeOffset now) =>
        AcceptedAt is not null ? "accepted" : RevokedAt is not null ? "revoked" : now >= ExpiresAt ? "expired" : "open";

    public bool TryAccept(Guid accountId, DateTimeOffset now)
    {
        if (!IsOpen(now))
        {
            return false;
        }

        AcceptedBy = accountId;
        AcceptedAt = now;
        return true;
    }

    public void Revoke(DateTimeOffset now) => RevokedAt ??= now;

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

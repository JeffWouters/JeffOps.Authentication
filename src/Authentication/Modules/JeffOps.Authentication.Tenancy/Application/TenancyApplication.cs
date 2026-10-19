using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Tenancy.Domain;

namespace JeffOps.Authentication.Tenancy.Application;

/// <summary>Tenancy (docs/DESIGN.md §8.6). Bound from <see cref="SectionName"/>.</summary>
public sealed class TenancyOptions
{
    public const string SectionName = "JeffOps:Tenancy";

    /// <summary>How long an invitation link works. Default: 7 days.</summary>
    public TimeSpan InvitationLifetime { get; set; } = TimeSpan.FromDays(7);

    /// <summary>The open invitations a tenant may have at once. Default: 100.</summary>
    public int MaxOpenInvitationsPerTenant { get; set; } = 100;

    /// <summary>The directories one tenant may link. Default: 10.</summary>
    public int MaxDirectoriesPerTenant { get; set; } = 10;

    /// <summary>
    /// The permission a product's backend (client credentials) needs to create a tenant at signup. Default:
    /// <c>auth.tenants.create</c>.
    /// </summary>
    public string SignupPermission { get; set; } = "auth.tenants.create";

    /// <summary>
    /// Define the authorization policies the token server and the Enterprise module ask for, from tenancy roles: tenant
    /// administrators (<see cref="ManagePolicy"/>, <see cref="ScimTokenPolicy"/>) and platform operators
    /// (<see cref="OperatorPolicy"/>, <see cref="AccountAdministrationPolicy"/>). Default: true. A host with its own policies
    /// turns this off.
    /// </summary>
    public bool DefinePolicies { get; set; } = true;

    /// <summary>Tenant administrators of the caller's own tenant. Default: <c>auth.enterprise.manage</c>.</summary>
    public string ManagePolicy { get; set; } = "auth.enterprise.manage";

    /// <summary>Creating SCIM tokens: tenant administrators too. Default: <c>auth.enterprise.scim_tokens</c>.</summary>
    public string ScimTokenPolicy { get; set; } = "auth.enterprise.scim_tokens";

    /// <summary>Platform operators (administrators of the platform tenant). Default: <c>auth.enterprise.operate</c>.</summary>
    public string OperatorPolicy { get; set; } = "auth.enterprise.operate";

    /// <summary>Account administration (disable, enable accounts): operators. Default: <c>auth.accounts.manage</c>.</summary>
    public string AccountAdministrationPolicy { get; set; } = "auth.accounts.manage";

    /// <summary>The platform tenant, created once when there is none. Without a name, no platform tenant is created.</summary>
    public PlatformTenantOptions Platform { get; set; } = new();
}

/// <summary>The platform tenant: its administrators are the platform operators.</summary>
public sealed class PlatformTenantOptions
{
    /// <summary>Its name, for example <c>JeffOps</c>. Null: no platform tenant is created from configuration.</summary>
    public string? Name { get; set; }

    /// <summary>An Entra directory (tenant id) to link to it, so the platform's own people join it when they sign in.</summary>
    public Guid? EntraDirectoryId { get; set; }

    /// <summary>
    /// Operators by an external login of theirs, as (issuer, subject); for Entra the issuer is
    /// <c>https://login.microsoftonline.com/{tenant id}/v2.0</c> and the subject the user's object id. Each becomes an
    /// administrator of the platform tenant at startup and whenever they sign in, so the first operator needs no account id.
    /// Removing one here doesn't demote them; do that through the API.
    /// </summary>
    public IList<OperatorLogin> Operators { get; } = [];
}

public sealed class OperatorLogin
{
    public string? Issuer { get; set; }

    public string? Subject { get; set; }
}

public static class TenancyErrors
{
    public const string NotFound = "tenant_not_found";
    public const string MemberNotFound = "member_not_found";
    public const string AccountNotFound = "account_not_found";
    public const string InvalidName = "invalid_tenant_name";
    public const string InvalidStatus = "invalid_tenant_status";
    public const string LastAdmin = "last_admin";
    public const string DirectoryTaken = "directory_taken";
    public const string DirectoryNotYours = "directory_not_yours";
    public const string TooManyDirectories = "too_many_directories";
    public const string TooManyInvitations = "too_many_invitations";
    public const string InvalidEmail = "invalid_email";
    public const string InvitationInvalid = "invitation_invalid";
    public const string InvitationNotFound = "invitation_not_found";
    public const string TenantClosed = "tenant_closed";
}

/// <summary>
/// Who acts on a tenant: a platform operator (any tenant, no tenant-admin restrictions) or a tenant administrator (their own
/// tenant only). The endpoints establish which; the use cases only apply the rules that differ.
/// </summary>
public sealed record TenancyActor(Guid AccountId, bool IsOperator);

public interface ITenantRepository
{
    Task<Tenant?> FindAsync(Guid tenantId, CancellationToken cancellationToken);

    Task<Tenant?> FindPlatformAsync(CancellationToken cancellationToken);

    /// <summary>Tenants by name (case-insensitive substring) or all, newest first, at most <paramref name="take"/>.</summary>
    Task<IReadOnlyList<Tenant>> ListAsync(string? nameContains, int skip, int take, CancellationToken cancellationToken);

    Task<IReadOnlyDictionary<Guid, Tenant>> FindManyAsync(IReadOnlyCollection<Guid> tenantIds, CancellationToken cancellationToken);

    void Add(Tenant tenant);
}

public interface IMembershipRepository
{
    Task<Membership?> FindAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken);

    Task<IReadOnlyList<Membership>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken);

    /// <summary>The account's memberships, oldest first.</summary>
    Task<IReadOnlyList<Membership>> ListForAccountAsync(Guid accountId, CancellationToken cancellationToken);

    Task<int> CountAdminsAsync(Guid tenantId, CancellationToken cancellationToken);

    void Add(Membership membership);

    void Remove(Membership membership);
}

public interface IDirectoryLinkRepository
{
    Task<DirectoryLink?> FindAsync(string kind, string directoryId, CancellationToken cancellationToken);

    Task<IReadOnlyList<DirectoryLink>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken);

    void Add(DirectoryLink link);

    void Remove(DirectoryLink link);
}

public interface IInvitationRepository
{
    Task<Invitation?> FindAsync(Guid invitationId, CancellationToken cancellationToken);

    Task<Invitation?> FindByTokenHashAsync(string tokenHash, CancellationToken cancellationToken);

    Task<IReadOnlyList<Invitation>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken);

    Task<int> CountOpenAsync(Guid tenantId, DateTimeOffset now, CancellationToken cancellationToken);

    void Add(Invitation invitation);
}

public interface ITenancyUnitOfWork
{
    Task SaveChangesAsync(CancellationToken cancellationToken);

    /// <summary>Saves, or answers false (saving nothing) when the store refuses it, for example a uniqueness constraint.</summary>
    Task<bool> TrySaveUniqueAsync(CancellationToken cancellationToken);
}

/// <summary>A tenant as the API shows it.</summary>
public sealed record TenantDto(Guid Id, string Name, string Status, bool IsPlatform, DateTimeOffset CreatedAt);

/// <summary>A member: the account, its contact address (when known) and its role.</summary>
public sealed record MemberDto(Guid AccountId, string? Email, string Role, string Source, DateTimeOffset Since);

public static class TenancyMapping
{
    public static TenantDto ToDto(this Tenant tenant)
    {
        ArgumentNullException.ThrowIfNull(tenant);
        return new(tenant.Id, tenant.Name, tenant.Status.ToString(), tenant.IsPlatform, tenant.CreatedAt);
    }

    public static MemberDto ToDto(this Membership membership, string? email)
    {
        ArgumentNullException.ThrowIfNull(membership);
        return new(membership.AccountId, email, membership.Role.ToString(), membership.Source.ToString(), membership.CreatedAt);
    }

    /// <summary>The Entra directories an account has signed in from (the tenant ids of its Entra logins).</summary>
    public static IReadOnlySet<Guid> EntraDirectoriesOf(Account account)
    {
        ArgumentNullException.ThrowIfNull(account);
        const string prefix = "https://login.microsoftonline.com/";
        return account.ExternalLogins
            .Select(login => login.Issuer)
            .Where(issuer => issuer.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && issuer.EndsWith("/v2.0", StringComparison.OrdinalIgnoreCase))
            .Select(issuer => Guid.TryParse(issuer[prefix.Length..^"/v2.0".Length], out var directory) ? directory : Guid.Empty)
            .Where(directory => directory != Guid.Empty)
            .ToHashSet();
    }
}

/// <summary>
/// Joins accounts to tenants for the automatic sources (directory, SSO, SCIM, operators' seed): adds a membership when
/// there is none, raises a role when asked, never lowers one and never changes a membership's source.
/// </summary>
public sealed class MembershipJoin(IMembershipRepository memberships, ITenantRepository tenants, ITenancyUnitOfWork unitOfWork, TimeProvider time)
{
    /// <summary>Whether the account is now a member (false when the tenant doesn't exist or is closed).</summary>
    public async Task<bool> EnsureAsync(Guid tenantId, Guid accountId, MembershipRole role, MembershipSource source, CancellationToken cancellationToken)
    {
        if (await tenants.FindAsync(tenantId, cancellationToken).ConfigureAwait(false) is not { Status: not TenantStatus.Deleted })
        {
            return false;
        }

        if (await memberships.FindAsync(tenantId, accountId, cancellationToken).ConfigureAwait(false) is { } existing)
        {
            if (existing.Role >= role)
            {
                return true;
            }

            existing.RaiseTo(role);
        }
        else
        {
            memberships.Add(Membership.Create(tenantId, accountId, role, source, addedBy: null, time.GetUtcNow()));
        }

        // Two sign-ins racing to add the same membership: the second one finds it there.
        return await unitOfWork.TrySaveUniqueAsync(cancellationToken).ConfigureAwait(false)
            || await memberships.FindAsync(tenantId, accountId, cancellationToken).ConfigureAwait(false) is not null;
    }
}

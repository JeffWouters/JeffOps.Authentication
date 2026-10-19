using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Enterprise.Domain;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Enterprise.Application;

public interface IScimTokenRepository
{
    Task<ScimToken?> FindByHashAsync(string hash, CancellationToken cancellationToken);

    Task<ScimToken?> FindAsync(Guid tokenId, CancellationToken cancellationToken);

    Task<IReadOnlyList<ScimToken>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken);

    void Add(ScimToken token);
}

/// <summary>
/// A list's order (RFC 7644 §3.4.2.3): <paramref name="Attribute"/> canonical (<see cref="Users"/>, <see cref="Groups"/>),
/// compared case-insensitively; resources without a value come last ascending, first descending.
/// </summary>
public sealed record ScimSort(string Attribute, bool Descending)
{
    /// <summary>What users can be sorted by.</summary>
    public static IReadOnlyList<string> Users { get; } = ["userName", "externalId", "displayName", "name.givenName", "name.familyName", "meta.created", "meta.lastModified"];

    /// <summary>What groups can be sorted by.</summary>
    public static IReadOnlyList<string> Groups { get; } = ["displayName", "externalId", "meta.created", "meta.lastModified"];

    /// <summary>The canonical spelling of <paramref name="attribute"/> among <paramref name="supported"/>, or null.</summary>
    public static string? Canonical(string attribute, IReadOnlyList<string> supported)
    {
        ArgumentNullException.ThrowIfNull(attribute);
        ArgumentNullException.ThrowIfNull(supported);
        return supported.FirstOrDefault(known => string.Equals(known, attribute, StringComparison.OrdinalIgnoreCase));
    }
}

public interface IScimUserRepository
{
    Task<ScimUser?> FindAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken);

    Task<(IReadOnlyList<ScimUser> Page, int Total)> ListAsync(Guid tenantId, System.Linq.Expressions.Expression<Func<ScimUser, bool>>? filter, int skip, int take, ScimSort? sort, CancellationToken cancellationToken);

    /// <summary>The tenant's provisioned users among <paramref name="accountIds"/>, in one query.</summary>
    Task<IReadOnlyList<ScimUser>> FindManyAsync(Guid tenantId, IReadOnlyCollection<Guid> accountIds, CancellationToken cancellationToken);

    /// <summary>Whether another tenant has provisioned the account too.</summary>
    Task<bool> ProvisionedElsewhereAsync(Guid accountId, Guid tenantId, CancellationToken cancellationToken);

    void Add(ScimUser user);

    void Remove(ScimUser user);
}

public interface IScimGroupRepository
{
    Task<ScimGroup?> FindAsync(Guid tenantId, Guid groupId, CancellationToken cancellationToken);

    Task<(IReadOnlyList<ScimGroup> Page, int Total)> ListAsync(Guid tenantId, System.Linq.Expressions.Expression<Func<ScimGroup, bool>>? filter, int skip, int take, ScimSort? sort, CancellationToken cancellationToken);

    /// <summary>Like <see cref="ListAsync"/>, as views without members, which aren't read at all.</summary>
    Task<(IReadOnlyList<ScimGroupView> Page, int Total)> ListWithoutMembersAsync(Guid tenantId, System.Linq.Expressions.Expression<Func<ScimGroup, bool>>? filter, int skip, int take, ScimSort? sort, CancellationToken cancellationToken);

    Task<IReadOnlyList<ScimGroup>> ListForMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken);

    /// <summary>Which groups each of <paramref name="accountIds"/> is in, with the groups' names; members aren't loaded.</summary>
    Task<IReadOnlyList<(Guid AccountId, Guid GroupId, string DisplayName)>> ListMembershipsAsync(Guid tenantId, IReadOnlyCollection<Guid> accountIds, CancellationToken cancellationToken);

    void Add(ScimGroup group);

    void Remove(ScimGroup group);
}

/// <summary>SCIM error types (RFC 7644 §3.12), used as the error code.</summary>
public static class ScimErrors
{
    public const string Uniqueness = "uniqueness";
    public const string InvalidValue = "invalidValue";
    public const string InvalidFilter = "invalidFilter";
    public const string NoTarget = "noTarget";
    public const string NotFound = "notFound";
    public const string Unavailable = "unavailable";
    public const string InvalidSyntax = "invalidSyntax";
    public const string InvalidPath = "invalidPath";

    /// <summary>Not a SCIM <c>scimType</c>: the resource's version isn't one <c>If-Match</c> named (412).</summary>
    public const string PreconditionFailed = "precondition_failed";

    /// <summary>Not a SCIM <c>scimType</c>: another request changed the resource meanwhile (409).</summary>
    public const string ConcurrentChange = "concurrent_change";
}

/// <summary>Resource versions as SCIM ETags carry them (RFC 7644 §3.14).</summary>
public static class ScimVersions
{
    /// <summary>
    /// Null when <paramref name="ifMatch"/> allows <paramref name="version"/>: no precondition (null), or a list that names it.
    /// </summary>
    public static Error? Check(IReadOnlyList<int>? ifMatch, int version) =>
        ifMatch is null || ifMatch.Contains(version) ? null : Error.Conflict(ScimErrors.PreconditionFailed, "The resource has changed since the version If-Match names.");

    /// <summary>The error for a save another request overtook: a failed precondition when the caller gave one.</summary>
    public static Error Overtaken(IReadOnlyList<int>? ifMatch) => ifMatch is null
        ? Error.Conflict(ScimErrors.ConcurrentChange, "The resource changed while this request ran; read it and try again.")
        : Error.Conflict(ScimErrors.PreconditionFailed, "The resource has changed since the version If-Match names.");
}

/// <summary>The attributes of a provisioned user the token server keeps.</summary>
public sealed record ScimUserData(string UserName, string? ExternalId, string? GivenName, string? FamilyName, string? DisplayName, string? Email, bool Active);

/// <summary>A provisioned user as SCIM shows it; <see cref="Id"/> is the account id.</summary>
public sealed record ScimUserView(
    Guid Id,
    string UserName,
    string? ExternalId,
    string? GivenName,
    string? FamilyName,
    string? DisplayName,
    string Email,
    bool Active,
    DateTimeOffset Created,
    DateTimeOffset LastModified,
    int Version,
    IReadOnlyList<(Guid Id, string DisplayName)> Groups);

public sealed record ScimGroupView(Guid Id, string DisplayName, string? ExternalId, IReadOnlyList<Guid> Members, DateTimeOffset Created, DateTimeOffset LastModified, int Version);

/// <summary>
/// Applies provisioned user state to accounts and memberships. Shared by create, replace and patch so all run the same rules:
/// <list type="bullet">
/// <item>Emails must be well-formed addresses in one of the tenant's verified domains, so a tenant can provision (and link)
/// only people whose addresses it controls — never another tenant's users or an operator, and never squat on someone else's
/// address.</item>
/// <item>An existing account is linked only when its email is verified (an unverified self-registration can't capture a
/// provisioned identity).</item>
/// <item>Profile and status changes reach the account only when provisioning created it, since a linked account may belong
/// to other tenants too; it is disabled only while no other tenant provisions it, and enabled again only if provisioning
/// disabled it and no operator disabled it since.</item>
/// <item>The tenant membership changes first: when the tenant system fails, nothing is recorded and the identity provider's
/// retry starts over.</item>
/// <item>Deactivated users keep their group records but drop out of the members announced to authorization, so their
/// group-derived roles stop at once.</item>
/// <item>Group announcements and audit records wait for the save: the handler calls <see cref="CommittedAsync"/> once the
/// change is stored, so nothing is announced for a change another request overtook.</item>
/// </list>
/// Scoped: one request's pending announcements; each create, apply or delete starts afresh.
/// </summary>
public sealed class ScimProvisioning(
    IAccountRepository accounts,
    IUnitOfWork accountUnitOfWork,
    IScimUserRepository users,
    IScimGroupRepository groups,
    ITenantDomainRepository domains,
    ITenantMembershipProvisioner memberships,
    IEventPublisher events,
    IAuditSink audit,
    TimeProvider time)
{
    private readonly List<(ScimGroup Group, IReadOnlyList<Guid> Added, IReadOnlyList<Guid> Removed)> _announcements = [];
    private readonly List<AuditRecord> _audits = [];

    public async Task<Result<ScimUser>> CreateAsync(Guid tenantId, ScimUserData data, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(data);
        Discard();
        var now = time.GetUtcNow();

        if ((await users.ListAsync(tenantId, ScimFilters.ForUsers(ScimFilter.Eq("userName", data.UserName)).Value, 0, 1, null, cancellationToken).ConfigureAwait(false)).Total > 0)
        {
            return Error.Conflict(ScimErrors.Uniqueness, $"A user with userName '{data.UserName}' already exists.");
        }

        var email = EmailOf(data);
        if (email is null)
        {
            return Error.Validation([new ValidationFailure("emails", "A user needs an email address (or an email userName).")]);
        }

        if (await OwnedEmailAsync(tenantId, email, cancellationToken).ConfigureAwait(false) is { } notOwned)
        {
            return notOwned;
        }

        var account = await accounts.FindByEmailAsync(email, cancellationToken).ConfigureAwait(false);
        var created = account is not { EmailVerified: true };
        if (created)
        {
            account = Account.Register(email, Name(data) ?? email, emailVerified: true, now);
            accounts.Add(account);
        }

        if (await users.FindAsync(tenantId, account!.Id, cancellationToken).ConfigureAwait(false) is not null)
        {
            return Error.Conflict(ScimErrors.Uniqueness, "This person is already provisioned in the tenant.");
        }

        var user = ScimUser.Provision(tenantId, account.Id, created, now);
        user.Update(data.UserName, data.ExternalId, data.GivenName, data.FamilyName, data.DisplayName, data.Active, now);
        if (!data.Active && created)
        {
            user.RecordAccountDisabled(account.Disable(now));
        }

        // The membership first: if the tenant system is down, nothing is saved and the retry starts over.
        if (data.Active && await MembershipAsync(tenantId, account.Id, add: true, cancellationToken).ConfigureAwait(false) is { } failure)
        {
            return failure;
        }

        await accountUnitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        users.Add(user);

        // An existing account the tenant now provisions: never claimable by its provider without the owner (docs §8.2).
        Audit(created ? "scim.user_created" : "scim.account_linked", tenantId, account.Id, now, created ? AuditSeverity.Information : AuditSeverity.Warning,
            data.Active ? null : new Dictionary<string, string?> { ["active"] = "false" });
        return user;
    }

    public async Task<Result<ScimUser>> ApplyAsync(ScimUser user, ScimUserData data, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(data);
        Discard();
        var now = time.GetUtcNow();

        if (!string.Equals(user.UserName, data.UserName, StringComparison.OrdinalIgnoreCase)
            && (await users.ListAsync(user.TenantId, ScimFilters.ForUsers(ScimFilter.Eq("userName", data.UserName)).Value, 0, 1, null, cancellationToken).ConfigureAwait(false)).Total > 0)
        {
            return Error.Conflict(ScimErrors.Uniqueness, $"A user with userName '{data.UserName}' already exists.");
        }

        var account = user.CreatedAccount ? await accounts.FindAsync(user.AccountId, cancellationToken).ConfigureAwait(false) : null;
        var email = EmailOf(data);
        var emailChanged = account is not null && email is not null && !string.Equals(email, account.Email, StringComparison.OrdinalIgnoreCase);
        if (emailChanged && await OwnedEmailAsync(user.TenantId, email!, cancellationToken).ConfigureAwait(false) is { } notOwned)
        {
            return notOwned;
        }

        var wasActive = user.Active;
        if (wasActive != data.Active
            && await MembershipAsync(user.TenantId, user.AccountId, add: data.Active, cancellationToken).ConfigureAwait(false) is { } failure)
        {
            return failure;
        }

        user.Update(data.UserName, data.ExternalId, data.GivenName, data.FamilyName, data.DisplayName, data.Active, now);
        if (account is not null)
        {
            account.UpdateProfile(email, Name(data), now);
            if (!data.Active && !user.DisabledAccount
                && !await users.ProvisionedElsewhereAsync(account.Id, user.TenantId, cancellationToken).ConfigureAwait(false))
            {
                // Provisioning's own disable, also when an earlier attempt that another request overtook saved it already;
                // never an operator's.
                account.Disable(now);
                user.RecordAccountDisabled(!account.DisabledByOperator);
            }
            else if (data.Active && user.DisabledAccount)
            {
                // Not when an operator disabled the account since: their disable stands until an operator lifts it.
                account.Enable(now, byOperator: false);
                user.RecordAccountDisabled(false);
            }

            await accountUnitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        if (emailChanged)
        {
            Audit("scim.user_email_changed", user.TenantId, user.AccountId, now, AuditSeverity.Warning);
        }

        if (wasActive != data.Active)
        {
            Audit(data.Active ? "scim.user_reactivated" : "scim.user_deactivated", user.TenantId, user.AccountId, now, AuditSeverity.Warning);

            // Group roles follow: the user's groups are announced with or without them, once saved.
            foreach (var group in await groups.ListForMemberAsync(user.TenantId, user.AccountId, cancellationToken).ConfigureAwait(false))
            {
                group.MembersChanged(now);
                _announcements.Add((group, data.Active ? [user.AccountId] : [], data.Active ? [] : [user.AccountId]));
            }
        }

        return user;
    }

    /// <summary>
    /// Deprovisions: leaves the tenant (first — if the tenant system fails, nothing changes and the identity provider retries)
    /// and its groups; an account provisioning created is disabled unless another tenant provisions it too.
    /// </summary>
    public async Task<Error?> DeleteAsync(ScimUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        Discard();
        var now = time.GetUtcNow();

        if (user.Active && await MembershipAsync(user.TenantId, user.AccountId, add: false, cancellationToken).ConfigureAwait(false) is { } failure)
        {
            return failure;
        }

        if (user.CreatedAccount && await accounts.FindAsync(user.AccountId, cancellationToken).ConfigureAwait(false) is { } account
            && !await users.ProvisionedElsewhereAsync(account.Id, user.TenantId, cancellationToken).ConfigureAwait(false))
        {
            account.Disable(now);
            await accountUnitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        foreach (var group in await groups.ListForMemberAsync(user.TenantId, user.AccountId, cancellationToken).ConfigureAwait(false))
        {
            group.RemoveMembers([user.AccountId], now);
            _announcements.Add((group, [], [user.AccountId]));
        }

        users.Remove(user);
        Audit("scim.user_deprovisioned", user.TenantId, user.AccountId, now, AuditSeverity.Warning);
        return null;
    }

    /// <summary>
    /// Announces the group changes and writes the audit records of the last create, apply or delete. Call it only after the
    /// change was saved; a change that wasn't saved is never announced.
    /// </summary>
    public async Task CommittedAsync(CancellationToken cancellationToken)
    {
        var announcements = _announcements.ToList();
        var records = _audits.ToList();
        Discard();
        foreach (var (group, added, removed) in announcements)
        {
            await PublishMembershipAsync(group, added, removed, cancellationToken).ConfigureAwait(false);
        }

        foreach (var record in records)
        {
            await audit.WriteAsync(record, cancellationToken).ConfigureAwait(false);
        }
    }

    private void Discard()
    {
        _announcements.Clear();
        _audits.Clear();
    }

    private void Audit(string action, Guid tenantId, Guid accountId, DateTimeOffset now, AuditSeverity severity, IReadOnlyDictionary<string, string?>? details = null) =>
        _audits.Add(new AuditRecord(action, "account", accountId.ToString())
        {
            TenantId = tenantId,
            OccurredAt = now,
            Severity = severity,
            Details = details ?? new Dictionary<string, string?>(),
        });

    public async Task<ScimUserView> ViewAsync(ScimUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        return (await ViewsAsync([user], cancellationToken).ConfigureAwait(false))[0];
    }

    /// <summary>
    /// The SCIM views of <paramref name="page"/>, in order, with two reads however many users there are: their emails, and
    /// the groups they are in (names only; the groups' members aren't loaded).
    /// </summary>
    public async Task<IReadOnlyList<ScimUserView>> ViewsAsync(IReadOnlyList<ScimUser> page, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(page);
        if (page.Count == 0)
        {
            return [];
        }

        var ids = page.Select(user => user.AccountId).ToList();
        var emails = await accounts.FindEmailsAsync(ids, cancellationToken).ConfigureAwait(false);
        var memberships = (await groups.ListMembershipsAsync(page[0].TenantId, ids, cancellationToken).ConfigureAwait(false))
            .ToLookup(membership => membership.AccountId, membership => (membership.GroupId, membership.DisplayName));
        return [.. page.Select(user => View(user, emails.TryGetValue(user.AccountId, out var email) ? email : user.UserName, [.. memberships[user.AccountId]]))];
    }

    /// <summary>
    /// The view of a user just provisioned: in no group of the tenant yet (members must be provisioned first), with the
    /// account's email, which is the provisioned address (a linked account matched on it).
    /// </summary>
    public static ScimUserView NewView(ScimUser user, ScimUserData data)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(data);
        return View(user, EmailOf(data) is { } email ? Account.NormalizeEmail(email) : user.UserName, []);
    }

    private static ScimUserView View(ScimUser user, string email, IReadOnlyList<(Guid Id, string DisplayName)> memberOf) =>
        new(user.AccountId, user.UserName, user.ExternalId, user.GivenName, user.FamilyName, user.DisplayName, email, user.Active,
            user.Created, user.LastModified, user.Version, memberOf);

    /// <summary>The account's email, or the userName when the account is gone.</summary>
    public async Task<string> EmailAsync(ScimUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        return (await accounts.FindEmailsAsync([user.AccountId], cancellationToken).ConfigureAwait(false)).TryGetValue(user.AccountId, out var email) ? email : user.UserName;
    }

    /// <summary>
    /// Announces a group's members — the active ones: a deactivated user's group roles stop until they are active again — with
    /// the group's version, so a consumer can drop an announcement that arrives after a newer one.
    /// </summary>
    public async Task PublishMembershipAsync(ScimGroup group, IReadOnlyList<Guid> added, IReadOnlyList<Guid> removed, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(group);
        var inactive = (await users.FindManyAsync(group.TenantId, group.MemberIds, cancellationToken).ConfigureAwait(false))
            .Where(user => !user.Active).Select(user => user.AccountId).ToHashSet();
        await events.PublishAsync(
            new GroupMembershipChangedEvent(group.TenantId, group.Id, group.DisplayName, [.. group.MemberIds.Where(id => !inactive.Contains(id))], [.. added.Where(id => !inactive.Contains(id))], removed)
            {
                OccurredAt = time.GetUtcNow(),
                Version = group.Version,
            },
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Whether <paramref name="email"/> is a plain address (RFC 5322 addr-spec, dot-atom form): a local part of at most 64
    /// characters from the atom set, with single dots between atoms, and a host name of letters, digits and hyphens. Quoted
    /// local parts, address literals, comments, spaces and non-ASCII characters are refused.
    /// </summary>
    public static bool IsAddrSpec(string? email)
    {
        if (string.IsNullOrEmpty(email) || email.Length > 254)
        {
            return false;
        }

        var at = email.IndexOf('@', StringComparison.Ordinal);
        if (at <= 0 || at > 64 || at != email.LastIndexOf('@'))
        {
            return false;
        }

        var local = email[..at];
        var domain = email[(at + 1)..];
        return local.Split('.').All(atom => atom.Length > 0 && atom.All(IsAtext))
            && TenantDomain.Normalize(domain) is { } normalized
            && string.Equals(normalized, domain, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAtext(char character) =>
        char.IsAsciiLetterOrDigit(character) || "!#$%&'*+-/=?^_`{|}~".Contains(character, StringComparison.Ordinal);

    /// <summary>Refuses a malformed email, or one outside the tenant's verified domains.</summary>
    private async Task<Error?> OwnedEmailAsync(Guid tenantId, string email, CancellationToken cancellationToken)
    {
        if (!IsAddrSpec(email))
        {
            return Error.Validation([new ValidationFailure("emails", "The email address is not valid.")]);
        }

        var at = email.LastIndexOf('@');
        return TenantDomain.Normalize(email[(at + 1)..]) is { } domain
            && await domains.FindVerifiedAsync(domain, cancellationToken).ConfigureAwait(false) is { } verified
            && verified.TenantId == tenantId
            ? null
            : Error.Validation([new ValidationFailure("emails", "The email address must be in one of the tenant's verified domains.")]);
    }

    private async Task<Error?> MembershipAsync(Guid tenantId, Guid accountId, bool add, CancellationToken cancellationToken)
    {
        try
        {
            if (add)
            {
                await memberships.AddMemberAsync(tenantId, accountId, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await memberships.RemoveMemberAsync(tenantId, accountId, cancellationToken).ConfigureAwait(false);
            }

            return null;
        }
#pragma warning disable CA1031 // The tenant system being down is reported to the identity provider, which retries.
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
        {
            return Error.Unavailable(ScimErrors.Unavailable, "The tenant directory is unavailable. Try again.");
        }
    }

    private static string? EmailOf(ScimUserData data) =>
        !string.IsNullOrWhiteSpace(data.Email) ? data.Email.Trim()
        : data.UserName.Contains('@', StringComparison.Ordinal) ? data.UserName.Trim()
        : null;

    private static string? Name(ScimUserData data) =>
        data.DisplayName ?? (data.GivenName is null && data.FamilyName is null ? null : $"{data.GivenName} {data.FamilyName}".Trim());
}

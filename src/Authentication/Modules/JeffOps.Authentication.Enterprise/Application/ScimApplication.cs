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

/// <summary>A SCIM list filter: one attribute compared for equality (<c>userName eq "x"</c>), the form identity providers send.</summary>
public sealed record ScimFilter(string Attribute, string Value);

public interface IScimUserRepository
{
    Task<ScimUser?> FindAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken);

    Task<(IReadOnlyList<ScimUser> Page, int Total)> ListAsync(Guid tenantId, ScimFilter? filter, int skip, int take, CancellationToken cancellationToken);

    void Add(ScimUser user);

    void Remove(ScimUser user);
}

public interface IScimGroupRepository
{
    Task<ScimGroup?> FindAsync(Guid tenantId, Guid groupId, CancellationToken cancellationToken);

    Task<(IReadOnlyList<ScimGroup> Page, int Total)> ListAsync(Guid tenantId, ScimFilter? filter, int skip, int take, CancellationToken cancellationToken);

    Task<IReadOnlyList<ScimGroup>> ListForMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken);

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
/// an existing account is linked only when its email is verified (an unverified self-registration can't capture a
/// provisioned identity); profile and status changes reach the account only when provisioning created it, since a linked
/// account may belong to other tenants too.
/// </summary>
public sealed class ScimProvisioning(
    IAccountRepository accounts,
    IUnitOfWork accountUnitOfWork,
    IScimUserRepository users,
    IScimGroupRepository groups,
    ITenantMembershipProvisioner memberships,
    IEventPublisher events,
    TimeProvider time)
{
    public async Task<Result<ScimUser>> CreateAsync(Guid tenantId, ScimUserData data, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(data);
        var now = time.GetUtcNow();

        if ((await users.ListAsync(tenantId, new ScimFilter("userName", data.UserName), 0, 1, cancellationToken).ConfigureAwait(false)).Total > 0)
        {
            return Error.Conflict(ScimErrors.Uniqueness, $"A user with userName '{data.UserName}' already exists.");
        }

        var email = EmailOf(data);
        if (email is null)
        {
            return Error.Validation([new ValidationFailure("emails", "A user needs an email address (or an email userName).")]);
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
            account.Disable(now);
        }

        await accountUnitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        users.Add(user);

        if (data.Active && await MembershipAsync(tenantId, account.Id, add: true, cancellationToken).ConfigureAwait(false) is { } failure)
        {
            return failure;
        }

        return user;
    }

    public async Task<Result<ScimUser>> ApplyAsync(ScimUser user, ScimUserData data, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(data);
        var now = time.GetUtcNow();

        if (!string.Equals(user.UserName, data.UserName, StringComparison.OrdinalIgnoreCase)
            && (await users.ListAsync(user.TenantId, new ScimFilter("userName", data.UserName), 0, 1, cancellationToken).ConfigureAwait(false)).Total > 0)
        {
            return Error.Conflict(ScimErrors.Uniqueness, $"A user with userName '{data.UserName}' already exists.");
        }

        var wasActive = user.Active;
        user.Update(data.UserName, data.ExternalId, data.GivenName, data.FamilyName, data.DisplayName, data.Active, now);

        if (user.CreatedAccount && await accounts.FindAsync(user.AccountId, cancellationToken).ConfigureAwait(false) is { } account)
        {
            account.UpdateProfile(EmailOf(data), Name(data), now);
            _ = data.Active ? account.Enable(now) : account.Disable(now);
            await accountUnitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        if (wasActive != data.Active
            && await MembershipAsync(user.TenantId, user.AccountId, add: data.Active, cancellationToken).ConfigureAwait(false) is { } failure)
        {
            return failure;
        }

        return user;
    }

    /// <summary>Deprovisions: leaves the tenant and its groups; an account provisioning created is disabled.</summary>
    public async Task<Error?> DeleteAsync(ScimUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        var now = time.GetUtcNow();

        if (user.CreatedAccount && await accounts.FindAsync(user.AccountId, cancellationToken).ConfigureAwait(false) is { } account)
        {
            account.Disable(now);
            await accountUnitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        foreach (var group in await groups.ListForMemberAsync(user.TenantId, user.AccountId, cancellationToken).ConfigureAwait(false))
        {
            group.RemoveMembers([user.AccountId], now);
            await PublishMembershipAsync(group, [], [user.AccountId], cancellationToken).ConfigureAwait(false);
        }

        users.Remove(user);
        return user.Active ? await MembershipAsync(user.TenantId, user.AccountId, add: false, cancellationToken).ConfigureAwait(false) : null;
    }

    public async Task<ScimUserView> ViewAsync(ScimUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        var email = (await accounts.FindAsync(user.AccountId, cancellationToken).ConfigureAwait(false))?.Email ?? user.UserName;
        var memberOf = await groups.ListForMemberAsync(user.TenantId, user.AccountId, cancellationToken).ConfigureAwait(false);
        return new ScimUserView(user.AccountId, user.UserName, user.ExternalId, user.GivenName, user.FamilyName, user.DisplayName, email, user.Active,
            user.Created, user.LastModified, user.Version, [.. memberOf.Select(group => (group.Id, group.DisplayName))]);
    }

    public Task PublishMembershipAsync(ScimGroup group, IReadOnlyList<Guid> added, IReadOnlyList<Guid> removed, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(group);
        return events.PublishAsync(
            new GroupMembershipChangedEvent(group.TenantId, group.Id, group.DisplayName, group.MemberIds, added, removed) { OccurredAt = time.GetUtcNow() },
            cancellationToken);
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

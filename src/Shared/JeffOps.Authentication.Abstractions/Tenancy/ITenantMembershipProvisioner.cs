namespace JeffOps.Authentication.Abstractions.Tenancy;

/// <summary>
/// Adds and removes tenant members in the host's tenant system, for provisioning (SCIM). Memberships stay owned by the host;
/// the token server only asks.
/// </summary>
/// <remarks>Implementations throw when the tenant system can't be reached; the request is then answered 503.</remarks>
public interface ITenantMembershipProvisioner
{
    /// <summary>Makes the account a member of the tenant; does nothing if it already is one.</summary>
    Task AddMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken);

    /// <summary>Ends the account's membership of the tenant; does nothing if it isn't a member.</summary>
    Task RemoveMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken);
}

/// <summary>The default: provisioning records users and groups but leaves memberships to the host's own processes.</summary>
public sealed class NoMembershipProvisioning : ITenantMembershipProvisioner
{
    /// <summary>Does nothing; the host manages memberships itself.</summary>
    public Task AddMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>Does nothing; the host manages memberships itself.</summary>
    public Task RemoveMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken) => Task.CompletedTask;
}

namespace JeffOps.Authentication.Abstractions.Tenancy;

/// <summary>
/// Adds and removes tenant members in the host's tenant system, for provisioning (SCIM). Memberships stay owned by the host;
/// the token server only asks.
/// </summary>
/// <remarks>Implementations throw when the tenant system can't be reached; the request is then answered 503.</remarks>
public interface ITenantMembershipProvisioner
{
    Task AddMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken);

    Task RemoveMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken);
}

/// <summary>The default: provisioning records users and groups but leaves memberships to the host's own processes.</summary>
public sealed class NoMembershipProvisioning : ITenantMembershipProvisioner
{
    public Task AddMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task RemoveMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken) => Task.CompletedTask;
}

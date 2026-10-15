using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.SharedKernel.Domain;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Management;
using JeffOps.Authorization.Domain.Permissions;

namespace JeffOps.Authorization.Application.Management;

/// <summary>
/// Publishes committed changes as integration events. Resource services evict their decision caches on them; oversight
/// tooling alerts on privileged grants.
/// </summary>
public sealed class AuthorizationEventPublishers(IEventPublisher publisher, TimeProvider time) :
    IDomainEventHandler<RolePermissionsChanged>,
    IDomainEventHandler<RoleAssigned>,
    IDomainEventHandler<RoleRevoked>,
    IDomainEventHandler<PrivilegedAccessGranted>,
    IDomainEventHandler<PolicyChanged>,
    IDomainEventHandler<ScopesChanged>
{
    public Task HandleAsync(RolePermissionsChanged domainEvent, CancellationToken cancellationToken) =>
        PublishAsync(new RolePermissionsChangedEvent(domainEvent!.RoleId), cancellationToken);

    public Task HandleAsync(RoleAssigned domainEvent, CancellationToken cancellationToken) =>
        PublishAsync(new UserRoleAssignedEvent(domainEvent!.UserId, domainEvent.TenantId, domainEvent.RoleId), cancellationToken);

    public Task HandleAsync(RoleRevoked domainEvent, CancellationToken cancellationToken) =>
        PublishAsync(new UserRoleRevokedEvent(domainEvent!.UserId, domainEvent.TenantId, domainEvent.RoleId), cancellationToken);

    public Task HandleAsync(PrivilegedAccessGranted domainEvent, CancellationToken cancellationToken) =>
        PublishAsync(new PrivilegedAccessGrantedEvent(domainEvent!.UserId, domainEvent.TenantId, domainEvent.RoleId, domainEvent.RoleName, domainEvent.ExpiresAt, domainEvent.Watchers), cancellationToken);

    public Task HandleAsync(PolicyChanged domainEvent, CancellationToken cancellationToken) =>
        PublishAsync(new PolicyChangedEvent(domainEvent!.PolicyId), cancellationToken);

    public Task HandleAsync(ScopesChanged domainEvent, CancellationToken cancellationToken) =>
        PublishAsync(new ScopesChangedEvent(), cancellationToken);

    private Task PublishAsync(IntegrationEvent integrationEvent, CancellationToken cancellationToken) =>
        publisher.PublishAsync(integrationEvent with { OccurredAt = time.GetUtcNow() }, cancellationToken);
}

/// <summary>
/// Seeds the built-in scopes and roles the host declares, and keeps built-in roles in sync: a permission added to a
/// built-in role in code reaches existing deployments at the next start. Runs at every startup; idempotent.
/// </summary>
public sealed class ManagementSeeder(
    IScopeRepository scopes,
    IRoleRepository roles,
    IUnitOfWork unitOfWork,
    IScopeSeedProvider scopeSeed,
    IBuiltInRoleProvider builtInRoles,
    TimeProvider time)
{
    public async Task SeedAsync(CancellationToken cancellationToken)
    {
        var existingScopes = (await scopes.ListAsync(cancellationToken).ConfigureAwait(false)).Select(scope => scope.Id).ToHashSet(StringComparer.Ordinal);
        foreach (var seed in scopeSeed.Scopes.Where(seed => !existingScopes.Contains(Scope.Normalize(seed.Key))))
        {
            scopes.Add(Scope.Create(seed.Key, seed.Name, null, seed.ParentKey, isBuiltIn: true));
        }

        var globalRoles = (await roles.ListAsync(null, cancellationToken).ConfigureAwait(false)).Where(role => role.IsBuiltIn).ToDictionary(role => role.Name, StringComparer.Ordinal);
        foreach (var builtIn in builtInRoles.Roles)
        {
            if (!globalRoles.TryGetValue(builtIn.Name, out var role))
            {
                role = Role.Create(builtIn.Name, tenantId: null, time.GetUtcNow(), isBuiltIn: true, builtIn.IsSuperAdmin, builtIn.IsBreakGlass, builtIn.MinScopeKey, builtIn.ComplianceControls);
                roles.Add(role);
            }

            // Kept in sync with the definition: permissions dropped from it are withdrawn.
            var wanted = builtIn.Permissions.Select(Permission.Normalize).ToHashSet(StringComparer.Ordinal);
            foreach (var stale in role.PermissionCodes().Where(code => !wanted.Contains(code)).ToList())
            {
                role.RemovePermission(stale);
            }

            foreach (var permission in wanted)
            {
                role.AddPermission(permission);
            }
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
    }
}

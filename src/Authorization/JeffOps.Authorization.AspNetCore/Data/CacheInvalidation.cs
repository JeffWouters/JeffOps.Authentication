using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authorization.Contracts;

namespace JeffOps.Authorization.AspNetCore.Data;

/// <summary>
/// Evicts cached authorization data when the management service announces a change. Registered as
/// <see cref="IIntegrationEventHandler{TEvent}"/>s; the host's broker adapter dispatches the events. Without a broker the
/// cache lifetimes in <see cref="DecisionCacheOptions"/> bound how stale a decision can be.
/// </summary>
internal sealed class AuthorizationCacheInvalidator(SealedDecisionCache cache) :
    IIntegrationEventHandler<RolePermissionsChangedEvent>,
    IIntegrationEventHandler<UserRoleAssignedEvent>,
    IIntegrationEventHandler<UserRoleRevokedEvent>,
    IIntegrationEventHandler<PolicyChangedEvent>,
    IIntegrationEventHandler<ScopesChangedEvent>
{
    public Task HandleAsync(RolePermissionsChangedEvent integrationEvent, CancellationToken cancellationToken) =>
        cache.RemoveAsync(AuthorizationCacheKeys.RolePermissions, cancellationToken).AsTask();

    public Task HandleAsync(UserRoleAssignedEvent integrationEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(integrationEvent);
        return cache.RemoveAsync(AuthorizationCacheKeys.Assignments(integrationEvent.UserId, integrationEvent.TenantId), cancellationToken).AsTask();
    }

    public Task HandleAsync(UserRoleRevokedEvent integrationEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(integrationEvent);
        return cache.RemoveAsync(AuthorizationCacheKeys.Assignments(integrationEvent.UserId, integrationEvent.TenantId), cancellationToken).AsTask();
    }

    public Task HandleAsync(PolicyChangedEvent integrationEvent, CancellationToken cancellationToken) =>
        cache.RemoveAsync(AuthorizationCacheKeys.Policies, cancellationToken).AsTask();

    public Task HandleAsync(ScopesChangedEvent integrationEvent, CancellationToken cancellationToken) =>
        cache.RemoveAsync(AuthorizationCacheKeys.Scopes, cancellationToken).AsTask();
}

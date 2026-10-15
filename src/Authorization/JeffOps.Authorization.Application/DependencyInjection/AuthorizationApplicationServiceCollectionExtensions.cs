using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.SharedKernel.DependencyInjection;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Application.Features.Assignments;
using JeffOps.Authorization.Application.Features.GroupAssignments;
using JeffOps.Authorization.Application.Features.Permissions;
using JeffOps.Authorization.Application.Features.Policies;
using JeffOps.Authorization.Application.Features.RoleChanges;
using JeffOps.Authorization.Application.Features.Roles;
using JeffOps.Authorization.Application.Features.Scopes;
using JeffOps.Authorization.Application.Management;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace JeffOps.Authorization.Application.DependencyInjection;

public static class AuthorizationApplicationServiceCollectionExtensions
{
    /// <summary>Registers the management use cases, each explicitly. Called by <c>AddJeffOpsAuthorization</c>.</summary>
    public static IServiceCollection AddJeffOpsAuthorizationApplication(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IPermissionCatalogProvider, EmptyCatalog>();
        services.TryAddSingleton<IBuiltInRoleProvider, EmptyCatalog>();
        services.TryAddSingleton<IScopeSeedProvider, DefaultScopeSeed>();
        services.TryAddScoped<HeldPermissions>();
        services.TryAddScoped<ManagementGuard>();
        services.TryAddScoped<RoleChangeApplier>();
        services.TryAddScoped<ManagementAudit>();
        services.TryAddScoped<PermissionCatalog>();
        services.TryAddScoped<ManagementSeeder>();
        services.TryAddScoped<StoreDataSource>();

        services
            .AddHandler<ListRolesHandler>()
            .AddHandler<CreateRoleHandler>()
            .AddHandler<ChangeRolePermissionHandler>()
            .AddHandler<ListRoleChangesHandler>()
            .AddHandler<DecideRoleChangeHandler>()
            .AddHandler<GetApprovalSettingHandler>()
            .AddHandler<SetApprovalSettingHandler>()
            .AddHandler<AssignRoleHandler>()
            .AddHandler<RevokeAssignmentHandler>()
            .AddHandler<ListTenantAssignmentsHandler>()
            .AddHandler<RecertifyAssignmentHandler>()
            .AddHandler<AssignGroupRoleHandler>()
            .AddHandler<RevokeGroupAssignmentHandler>()
            .AddHandler<ListGroupAssignmentsHandler>()
            .AddHandler<SweepExpiredAssignmentsHandler>()
            .AddHandler<ListPoliciesHandler>()
            .AddHandler<UpsertPolicyHandler>()
            .AddHandler<DeletePolicyHandler>()
            .AddHandler<SimulateDecisionHandler>()
            .AddHandler<ListScopesHandler>()
            .AddHandler<UpsertScopeHandler>()
            .AddHandler<DeleteScopeHandler>()
            .AddHandler<RegisterPermissionsHandler>()
            .AddHandler<GetCatalogHandler>()
            .AddHandlerValidation();

        services.AddDomainEventDispatcher();
        services.AddDomainEventHandler<AuthorizationEventPublishers>();
        services.TryAddScoped<GroupSync>();
        services.AddScoped<IIntegrationEventHandler<GroupMembershipChangedEvent>>(provider => provider.GetRequiredService<GroupSync>());
        services.AddScoped<IIntegrationEventHandler<GroupDeletedEvent>>(provider => provider.GetRequiredService<GroupSync>());
        return services;
    }
}

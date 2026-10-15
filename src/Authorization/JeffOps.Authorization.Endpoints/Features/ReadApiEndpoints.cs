using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authorization.Application.Features.Permissions;
using JeffOps.Authorization.Application.Management;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Endpoints.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace JeffOps.Authorization.Endpoints.Features;

/// <summary>
/// The read API resource services cache from (<see cref="AuthorizationRoutes"/>), and self-registration of their permissions.
/// </summary>
internal static class ReadApiEndpoints
{
    public static void Map(RouteGroupBuilder root)
    {
        var read = root.MapGroup(string.Empty).WithTags("Authorization data").AddEndpointFilter<ReadApiFilter>();

        read.MapGet(AuthorizationRoutes.UserAssignments, async (Guid userId, Guid tenantId, StoreDataSource source, HttpContext context) =>
            TypedResults.Ok(await source.GetUserAssignmentsAsync(userId, tenantId, context.RequestAborted).ConfigureAwait(false)))
            .WithName("GetUserAssignments");

        read.MapGet(AuthorizationRoutes.RolePermissions, async (StoreDataSource source, HttpContext context) =>
            TypedResults.Ok(await source.GetRolePermissionsAsync(context.RequestAborted).ConfigureAwait(false)))
            .WithName("GetRolePermissions");

        read.MapGet(AuthorizationRoutes.Policies, async (StoreDataSource source, HttpContext context) =>
            TypedResults.Ok(await source.GetPoliciesAsync(context.RequestAborted).ConfigureAwait(false)))
            .WithName("GetAttributePolicies");

        read.MapGet(AuthorizationRoutes.Scopes, async (StoreDataSource source, HttpContext context) =>
            TypedResults.Ok(await source.GetScopesAsync(context.RequestAborted).ConfigureAwait(false)))
            .WithName("GetScopes");

        root.MapPost(AuthorizationRoutes.RegisterPermissions, async (RegisterPermissionsRequest request, ICommandHandler<RegisterPermissionsCommand, int> handler, HttpContext context) =>
            (await handler.HandleAsync(new RegisterPermissionsCommand(context.Caller(), request), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .WithTags("Authorization data")
            .WithName("RegisterPermissions");
    }
}

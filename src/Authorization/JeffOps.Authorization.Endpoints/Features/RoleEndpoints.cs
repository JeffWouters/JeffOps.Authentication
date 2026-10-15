using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authorization.Application.Features.RoleChanges;
using JeffOps.Authorization.Application.Features.Roles;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Management;
using JeffOps.Authorization.Endpoints.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace JeffOps.Authorization.Endpoints.Features;

/// <summary>Roles, their permissions, and the four-eyes approval queue.</summary>
internal static class RoleEndpoints
{
    public static void Map(RouteGroupBuilder root)
    {
        var roles = root.MapGroup(ManagementRoutes.Roles).WithTags("Roles");
        roles.MapGet("/", async (IQueryHandler<ListRolesQuery, IReadOnlyList<RoleDto>> handler, HttpContext context) =>
            (await handler.HandleAsync(new ListRolesQuery(context.Caller()), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .WithName("ListRoles");

        roles.MapPost("/", async (CreateRoleRequest request, ICommandHandler<CreateRoleCommand, RoleDto> handler, HttpContext context) =>
            (await handler.HandleAsync(new CreateRoleCommand(context.Caller(), request), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("CreateRole");

        roles.MapPost("/{roleId:guid}/permissions", async (Guid roleId, RolePermissionRequest request, ICommandHandler<ChangeRolePermissionCommand, ChangeOutcomeDto> handler, HttpContext context) =>
            (await handler.HandleAsync(new ChangeRolePermissionCommand(context.Caller(), roleId, request.Permission, Add: true), context.RequestAborted).ConfigureAwait(false)).ToChangeResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("AddRolePermission");

        roles.MapDelete("/{roleId:guid}/permissions/{permission}", async (Guid roleId, string permission, ICommandHandler<ChangeRolePermissionCommand, ChangeOutcomeDto> handler, HttpContext context) =>
            (await handler.HandleAsync(new ChangeRolePermissionCommand(context.Caller(), roleId, permission, Add: false), context.RequestAborted).ConfigureAwait(false)).ToChangeResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("RemoveRolePermission");

        var changes = root.MapGroup(ManagementRoutes.RoleChanges).WithTags("Role changes");
        changes.MapGet("/", async (RoleChangeStatus? status, IQueryHandler<ListRoleChangesQuery, IReadOnlyList<RoleChangeRequestDto>> handler, HttpContext context) =>
            (await handler.HandleAsync(new ListRoleChangesQuery(context.Caller(), status), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .WithName("ListRoleChanges");

        changes.MapPost("/{requestId:guid}/approve", (Guid requestId, DecideRoleChangeRequest? request, ICommandHandler<DecideRoleChangeCommand, RoleChangeRequestDto> handler, HttpContext context) =>
            DecideAsync(requestId, approve: true, request, handler, context))
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("ApproveRoleChange");

        changes.MapPost("/{requestId:guid}/reject", (Guid requestId, DecideRoleChangeRequest? request, ICommandHandler<DecideRoleChangeCommand, RoleChangeRequestDto> handler, HttpContext context) =>
            DecideAsync(requestId, approve: false, request, handler, context))
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("RejectRoleChange");

        var approval = root.MapGroup(ManagementRoutes.ApprovalSetting).WithTags("Role changes");
        approval.MapGet("/", async (IQueryHandler<GetApprovalSettingQuery, ApprovalSettingDto> handler, HttpContext context) =>
            (await handler.HandleAsync(new GetApprovalSettingQuery(context.Caller()), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .WithName("GetApprovalSetting");

        approval.MapPut("/", async (SetApprovalSettingRequest request, ICommandHandler<SetApprovalSettingCommand, ChangeOutcomeDto> handler, HttpContext context) =>
            (await handler.HandleAsync(new SetApprovalSettingCommand(context.Caller(), request.Require, request.Global), context.RequestAborted).ConfigureAwait(false)).ToChangeResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("SetApprovalSetting");
    }

    private static async Task<IResult> DecideAsync(
        Guid requestId,
        bool approve,
        DecideRoleChangeRequest? request,
        ICommandHandler<DecideRoleChangeCommand, RoleChangeRequestDto> handler,
        HttpContext context) =>
        (await handler.HandleAsync(new DecideRoleChangeCommand(context.Caller(), requestId, approve, request?.Note), context.RequestAborted).ConfigureAwait(false)).ToHttpResult();
}

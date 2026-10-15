using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authorization.Application.Features.Assignments;
using JeffOps.Authorization.Application.Features.GroupAssignments;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Endpoints.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace JeffOps.Authorization.Endpoints.Features;

/// <summary>Role assignments: grant, revoke, list, recertify.</summary>
internal static class AssignmentEndpoints
{
    public static void Map(RouteGroupBuilder root)
    {
        var group = root.MapGroup(ManagementRoutes.Assignments).WithTags("Assignments");

        group.MapGet("/", async (Guid? tenantId, IQueryHandler<ListTenantAssignmentsQuery, IReadOnlyList<AssignmentDto>> handler, HttpContext context) =>
        {
            var caller = context.Caller();
            if ((tenantId ?? caller.EffectiveTenantId) is not { } tenant)
            {
                return TypedResults.Problem(detail: "Name the tenant.", statusCode: StatusCodes.Status400BadRequest, extensions: new Dictionary<string, object?> { ["code"] = "tenant_required" });
            }

            return (await handler.HandleAsync(new ListTenantAssignmentsQuery(caller, tenant), context.RequestAborted).ConfigureAwait(false)).ToHttpResult();
        }).WithName("ListAssignments");

        group.MapPost("/", async (AssignRoleRequest request, ICommandHandler<AssignRoleCommand, ChangeOutcomeDto> handler, HttpContext context) =>
            (await handler.HandleAsync(new AssignRoleCommand(context.Caller(), request), context.RequestAborted).ConfigureAwait(false)).ToChangeResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("AssignRole");

        group.MapDelete("/{assignmentId:guid}", async (Guid assignmentId, ICommandHandler<RevokeAssignmentCommand> handler, HttpContext context) =>
            (await handler.HandleAsync(new RevokeAssignmentCommand(context.Caller(), assignmentId), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("RevokeAssignment");

        var groups = root.MapGroup(ManagementRoutes.GroupAssignments).WithTags("Assignments");
        groups.MapGet("/", async (Guid? tenantId, IQueryHandler<ListGroupAssignmentsQuery, IReadOnlyList<GroupAssignmentDto>> handler, HttpContext context) =>
        {
            var caller = context.Caller();
            if ((tenantId ?? caller.EffectiveTenantId) is not { } tenant)
            {
                return TypedResults.Problem(detail: "Name the tenant.", statusCode: StatusCodes.Status400BadRequest, extensions: new Dictionary<string, object?> { ["code"] = "tenant_required" });
            }

            return (await handler.HandleAsync(new ListGroupAssignmentsQuery(caller, tenant), context.RequestAborted).ConfigureAwait(false)).ToHttpResult();
        }).WithName("ListGroupAssignments");
        groups.MapPost("/", async (AssignGroupRoleRequest request, ICommandHandler<AssignGroupRoleCommand, GroupAssignmentDto> handler, HttpContext context) =>
            (await handler.HandleAsync(new AssignGroupRoleCommand(context.Caller(), request), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("AssignGroupRole");
        groups.MapDelete("/{assignmentId:guid}", async (Guid assignmentId, ICommandHandler<RevokeGroupAssignmentCommand> handler, HttpContext context) =>
            (await handler.HandleAsync(new RevokeGroupAssignmentCommand(context.Caller(), assignmentId), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("RevokeGroupAssignment");

        group.MapPost("/{assignmentId:guid}/recertify", async (Guid assignmentId, RecertifyRequest request, ICommandHandler<RecertifyAssignmentCommand> handler, HttpContext context) =>
            (await handler.HandleAsync(new RecertifyAssignmentCommand(context.Caller(), assignmentId, request.ExpiresAt), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("RecertifyAssignment");
    }
}

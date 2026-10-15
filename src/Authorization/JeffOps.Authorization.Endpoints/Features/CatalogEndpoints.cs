using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authorization.Application.Features.Permissions;
using JeffOps.Authorization.Application.Features.Policies;
using JeffOps.Authorization.Application.Features.Scopes;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Endpoints.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace JeffOps.Authorization.Endpoints.Features;

/// <summary>Attribute policies, the scope hierarchy, and the permission catalog.</summary>
internal static class CatalogEndpoints
{
    public static void Map(RouteGroupBuilder root)
    {
        var policies = root.MapGroup(ManagementRoutes.Policies).WithTags("Policies");
        policies.MapGet("/", async (IQueryHandler<ListPoliciesQuery, IReadOnlyList<AttributePolicyDto>> handler, HttpContext context) =>
            (await handler.HandleAsync(new ListPoliciesQuery(context.Caller()), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .WithName("ListPolicies");

        policies.MapPost("/", async (UpsertPolicyRequest request, ICommandHandler<UpsertPolicyCommand, AttributePolicyDto> handler, HttpContext context) =>
            (await handler.HandleAsync(new UpsertPolicyCommand(context.Caller(), null, request), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("CreatePolicy");

        policies.MapPut("/{policyId:guid}", async (Guid policyId, UpsertPolicyRequest request, ICommandHandler<UpsertPolicyCommand, AttributePolicyDto> handler, HttpContext context) =>
            (await handler.HandleAsync(new UpsertPolicyCommand(context.Caller(), policyId, request), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("UpdatePolicy");

        policies.MapDelete("/{policyId:guid}", async (Guid policyId, ICommandHandler<DeletePolicyCommand> handler, HttpContext context) =>
            (await handler.HandleAsync(new DeletePolicyCommand(context.Caller(), policyId), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("DeletePolicy");

        policies.MapPost("/simulate", async (SimulateRequest request, IQueryHandler<SimulateDecisionQuery, SimulateResponse> handler, HttpContext context) =>
            (await handler.HandleAsync(new SimulateDecisionQuery(context.Caller(), request), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .WithName("SimulateDecision");

        var scopes = root.MapGroup(ManagementRoutes.Scopes).WithTags("Scopes");
        scopes.MapGet("/", async (IQueryHandler<ListScopesQuery, IReadOnlyList<ScopeDto>> handler, HttpContext context) =>
            (await handler.HandleAsync(new ListScopesQuery(), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .WithName("ListScopes");

        scopes.MapPost("/", async (UpsertScopeRequest request, ICommandHandler<UpsertScopeCommand, ScopeDto> handler, HttpContext context) =>
            (await handler.HandleAsync(new UpsertScopeCommand(context.Caller(), request, Create: true), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("CreateScope");

        scopes.MapPut("/{key}", async (string key, UpsertScopeRequest request, ICommandHandler<UpsertScopeCommand, ScopeDto> handler, HttpContext context) =>
            (await handler.HandleAsync(new UpsertScopeCommand(context.Caller(), request with { Key = key }, Create: false), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("UpdateScope");

        scopes.MapDelete("/{key}", async (string key, ICommandHandler<DeleteScopeCommand> handler, HttpContext context) =>
            (await handler.HandleAsync(new DeleteScopeCommand(context.Caller(), key), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .AddEndpointFilter<ManagementChangeFilter>()
            .WithName("DeleteScope");

        root.MapGet(ManagementRoutes.Catalog, async (IQueryHandler<GetCatalogQuery, IReadOnlyList<CatalogEntryDto>> handler, HttpContext context) =>
            (await handler.HandleAsync(new GetCatalogQuery(), context.RequestAborted).ConfigureAwait(false)).ToHttpResult())
            .WithTags("Permissions")
            .WithName("GetPermissionCatalog");
    }
}

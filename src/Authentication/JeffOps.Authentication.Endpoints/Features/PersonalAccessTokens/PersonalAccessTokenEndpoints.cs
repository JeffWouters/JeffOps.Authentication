using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Abstractions.Contracts;
using JeffOps.Authentication.Application.Features.PersonalAccessTokens;
using JeffOps.Authentication.Endpoints.Http;
using JeffOps.Authentication.SharedKernel.Handlers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace JeffOps.Authentication.Endpoints.Features.PersonalAccessTokens;

/// <summary>The caller's own personal access tokens: create, list, revoke.</summary>
internal static class PersonalAccessTokenEndpoints
{
    public static void Map(IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("account/pats")
            .WithTags("Personal access tokens")
            .RequireAuthorization(Callers.TokenPolicy);

        group.MapPost("/", CreateAsync).WithName("CreatePersonalAccessToken");
        group.MapGet("/", ListAsync).WithName("ListPersonalAccessTokens");
        group.MapDelete("/{id:guid}", RevokeAsync).WithName("RevokePersonalAccessToken");
    }

    private static async Task<IResult> CreateAsync(
        CreatePersonalAccessTokenRequest request,
        HttpContext context,
        ICommandHandler<CreatePatCommand, CreatePatResult> handler,
        ClaimNames names)
    {
        if (Callers.AsUser(context.User, names) is not { } caller)
        {
            return TypedResults.Forbid();
        }

        var result = await handler.HandleAsync(
            new CreatePatCommand(caller, request.Name, request.ExpiresInDays, request.Permissions ?? [], request.AllowSensitiveActions),
            context.RequestAborted).ConfigureAwait(false);

        return result.ToHttpResult(created => TypedResults.Ok(new CreatePersonalAccessTokenResponse(created.Id, created.Name, created.Secret, created.ExpiresAt)));
    }

    private static async Task<IResult> ListAsync(HttpContext context, IQueryHandler<ListPatsQuery, IReadOnlyList<PatSummary>> handler, ClaimNames names)
    {
        if (Callers.AsUser(context.User, names) is not { } caller)
        {
            return TypedResults.Forbid();
        }

        var result = await handler.HandleAsync(new ListPatsQuery(caller), context.RequestAborted).ConfigureAwait(false);
        return result.ToHttpResult(list => TypedResults.Ok(list.Select(token => new PersonalAccessTokenDto(
            token.Id, token.Name, token.CreatedAt, token.ExpiresAt, token.LastUsedAt, token.Revoked, token.Active, token.Permissions, token.AllowSensitiveActions)).ToList()));
    }

    private static async Task<IResult> RevokeAsync(Guid id, HttpContext context, ICommandHandler<RevokePatCommand> handler, ClaimNames names)
    {
        if (Callers.AsUser(context.User, names) is not { } caller)
        {
            return TypedResults.Forbid();
        }

        return (await handler.HandleAsync(new RevokePatCommand(caller, id), context.RequestAborted).ConfigureAwait(false)).ToHttpResult();
    }
}

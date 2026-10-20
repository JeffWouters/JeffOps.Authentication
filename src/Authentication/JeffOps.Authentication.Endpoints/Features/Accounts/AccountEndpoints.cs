using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Abstractions.Contracts;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Features.Accounts;
using JeffOps.Authentication.Endpoints.Http;
using JeffOps.Authentication.SharedKernel.Handlers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using OpenIddict.Validation.AspNetCore;

namespace JeffOps.Authentication.Endpoints.Features.Accounts;

/// <summary>Account administration for operators, and account lookups for services.</summary>
internal static class AccountEndpoints
{
    public static void Map(IEndpointRouteBuilder endpoints, TokenServerOptions options)
    {
        // Operators: the host's authorization (for example JeffOps.Authorization.AspNetCore) decides who holds the permission.
        var admin = endpoints.MapGroup("admin/accounts")
            .WithTags("Account administration")
            .RequireAuthorization(Callers.TokenPolicy)
            .RequireAuthorization(options.AccountAdministrationPermission);

        admin.MapPost("/{id:guid}/disable", (Guid id, HttpContext context, ICommandHandler<SetAccountStatusCommand> handler, ClaimNames names) =>
            SetStatusAsync(id, disable: true, context, handler, names));
        admin.MapPost("/{id:guid}/enable", (Guid id, HttpContext context, ICommandHandler<SetAccountStatusCommand> handler, ClaimNames names) =>
            SetStatusAsync(id, disable: false, context, handler, names));

        // Irreversible, so with a recent multi-factor sign-in (when sensitive actions need one), as the operator themselves.
        admin.MapDelete("/{id:guid}", (Guid id, HttpContext context, ICommandHandler<DeleteAccountCommand> handler, ClaimNames names) =>
            Callers.OwnSessionAccount(context.User, names) is { } operatorId
                ? DeleteAsync(new DeleteAccountCommand(operatorId, id, AccountDeletionReasons.Operator), context, handler, names, options)
                : Task.FromResult<IResult>(TypedResults.NotFound()));

        admin.MapPost("/{id:guid}/sessions/revoke", async (Guid id, HttpContext context, ICommandHandler<RevokeSessionsCommand> handler, ClaimNames names) =>
            Callers.OwnSessionAccount(context.User, names) is { } operatorId
                ? (await handler.HandleAsync(new RevokeSessionsCommand(operatorId, id), context.RequestAborted).ConfigureAwait(false)).ToHttpResult()
                : TypedResults.NotFound());

        // Users: sign out everywhere (every device and client), from their own session.
        endpoints.MapPost("account/sessions/revoke", async (HttpContext context, ICommandHandler<RevokeSessionsCommand> handler, ClaimNames names) =>
            Callers.OwnSessionAccount(context.User, names) is { } accountId
                ? (await handler.HandleAsync(new RevokeSessionsCommand(accountId, accountId), context.RequestAborted).ConfigureAwait(false)).ToHttpResult()
                : TypedResults.Forbid())
            .WithTags("Account")
            .RequireAuthorization(Callers.TokenPolicy);

        // Users: delete their own account, from their own session (not through a PAT or while acting as someone else).
        endpoints.MapDelete("account", (HttpContext context, ICommandHandler<DeleteAccountCommand> handler, ClaimNames names) =>
            Callers.OwnSessionAccount(context.User, names) is { } accountId
                ? DeleteAsync(new DeleteAccountCommand(accountId, accountId, AccountDeletionReasons.Requested), context, handler, names, options)
                : Task.FromResult<IResult>(TypedResults.Forbid()))
            .WithTags("Account")
            .RequireAuthorization(Callers.TokenPolicy);

        // Services only: a service principal holding the lookup permission (I8). Users can't enumerate accounts.
        var directory = endpoints.MapGroup("directory/accounts")
            .WithTags("Account directory")
            .RequireAuthorization(Callers.TokenPolicy)
            .RequireAuthorization(new AuthorizationPolicyBuilder(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
                .RequireAuthenticatedUser()
                .RequireAssertion(context => Callers.IsServiceWithPermission(
                    context.User,
                    (context.Resource as HttpContext)?.RequestServices.GetService(typeof(ClaimNames)) as ClaimNames ?? ClaimNames.Default,
                    options.DirectoryLookupPermission))
                .Build());

        directory.MapGet("/{id:guid}", async (Guid id, IQueryHandler<GetAccountContactQuery, AccountContact> handler, CancellationToken cancellationToken) =>
            (await handler.HandleAsync(new GetAccountContactQuery(id), cancellationToken).ConfigureAwait(false)).ToHttpResult(ToDto));
        directory.MapGet("/", async (string email, IQueryHandler<FindAccountByEmailQuery, AccountContact> handler, CancellationToken cancellationToken) =>
            (await handler.HandleAsync(new FindAccountByEmailQuery(email), cancellationToken).ConfigureAwait(false)).ToHttpResult(ToDto));
    }

    private static async Task<IResult> SetStatusAsync(Guid id, bool disable, HttpContext context, ICommandHandler<SetAccountStatusCommand> handler, ClaimNames names)
    {
        // Only an operator acting as themselves: not while impersonating, acting on a managed tenant, or through a PAT.
        if (Callers.OwnSessionAccount(context.User, names) is not { } operatorId)
        {
            return TypedResults.NotFound();
        }

        return (await handler.HandleAsync(new SetAccountStatusCommand(operatorId, id, disable), context.RequestAborted).ConfigureAwait(false)).ToHttpResult();
    }

    private static async Task<IResult> DeleteAsync(
        DeleteAccountCommand command, HttpContext context, ICommandHandler<DeleteAccountCommand> handler, ClaimNames names, TokenServerOptions options)
    {
        if (options.Mfa.RequireForSensitiveActions && !AccessContextReader.IsSteppedUp(context.User, names))
        {
            context.Response.Headers.WWWAuthenticate =
                "Bearer error=\"insufficient_user_authentication\", error_description=\"A multi-factor sign-in is required.\"";
            return TypedResults.Problem(
                detail: "Deleting an account requires a multi-factor sign-in (step-up).",
                statusCode: StatusCodes.Status403Forbidden,
                extensions: new Dictionary<string, object?> { ["code"] = "step_up_required" });
        }

        return (await handler.HandleAsync(command, context.RequestAborted).ConfigureAwait(false)).ToHttpResult();
    }

    private static IResult ToDto(AccountContact contact) =>
        TypedResults.Ok(new AccountContactDto(contact.Id, contact.Email, contact.DisplayName, contact.EmailVerified));
}

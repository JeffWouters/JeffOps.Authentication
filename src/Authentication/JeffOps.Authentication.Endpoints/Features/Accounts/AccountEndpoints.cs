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

        // Services only: a service principal holding the lookup permission (I8). Users can't enumerate accounts.
        var directory = endpoints.MapGroup("directory/accounts")
            .WithTags("Account directory")
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
        if (Callers.AsUser(context.User, names) is not { IsImpersonation: false, IsDelegated: false, IsPatDerived: false } caller)
        {
            return TypedResults.NotFound();
        }

        return (await handler.HandleAsync(new SetAccountStatusCommand(caller.AccountId, id, disable), context.RequestAborted).ConfigureAwait(false)).ToHttpResult();
    }

    private static IResult ToDto(AccountContact contact) =>
        TypedResults.Ok(new AccountContactDto(contact.Id, contact.Email, contact.DisplayName, contact.EmailVerified));
}

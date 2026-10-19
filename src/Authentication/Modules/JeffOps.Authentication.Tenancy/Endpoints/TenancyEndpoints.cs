using System.Text.Encodings.Web;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authentication.Tenancy.Application;
using JeffOps.Authentication.Tenancy.Application.Features.Directories;
using JeffOps.Authentication.Tenancy.Application.Features.Invitations;
using JeffOps.Authentication.Tenancy.Application.Features.Members;
using JeffOps.Authentication.Tenancy.Application.Features.Signup;
using JeffOps.Authentication.Tenancy.Application.Features.Tenants;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Tenancy.Endpoints;

public sealed record CreateTenantRequest(string Name, Guid? FirstAdmin = null);

public sealed record UpdateTenantRequest(string? Name = null, string? Status = null);

public sealed record AddMemberRequest(Guid AccountId, string Role = "Member");

public sealed record SetRoleRequest(string Role);

public sealed record LinkDirectoryRequest(Guid EntraDirectoryId);

public sealed record CreateInvitationRequest(string? Email = null, string? Role = null);

/// <summary>A new invitation: the link to hand to the invitee (shown once) and its details.</summary>
public sealed record InvitationLinkDto(Uri Link, InvitationDto Invitation);

public sealed record AcceptInvitationRequest(string Token);

public sealed record SignupRequest(string Name, Guid AdminAccountId, Guid? EntraDirectoryId = null);

public static class TenancyEndpointRouteBuilderExtensions
{
    /// <summary>Operators: every tenant.</summary>
    public const string OperatorRoutes = "tenancy/tenants";

    /// <summary>Tenant administrators: the session's tenant.</summary>
    public const string TenantRoutes = "tenancy/tenant";

    /// <summary>Any signed-in user: the tenants they belong to.</summary>
    public const string MembershipsRoute = "tenancy/memberships";

    public const string AcceptRoute = "tenancy/invitations/accept";

    /// <summary>Products' backends: a tenant for the person signing up.</summary>
    public const string SignupRoute = "tenancy/signup";

    /// <summary>The page an invitation link opens.</summary>
    public const string InvitationPage = "invitations";

    /// <summary>
    /// Maps the tenancy API and the invitation page (docs/DESIGN.md §8.6). The API takes only the token server's own access
    /// tokens (scope <c>account</c>); changes need a stepped-up session.
    /// </summary>
    public static IEndpointRouteBuilder MapJeffOpsTenancy(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        const string tokenPolicy = AccountApi.PolicyName;

        // ---- Operators -------------------------------------------------------------------------------------------------
        var operators = endpoints.MapGroup(OperatorRoutes).WithTags("Tenancy (operators)").RequireAuthorization(tokenPolicy).AddEndpointFilter<OperatorFilter>();

        operators.MapGet(string.Empty, async (string? name, int? skip, int? take, HttpContext context, IQueryHandler<ListTenantsQuery, IReadOnlyList<TenantDto>> handler) =>
            ToResult(await handler.HandleAsync(new ListTenantsQuery(Operator(context), name, skip ?? 0, take ?? 50), context.RequestAborted).ConfigureAwait(false)));
        operators.MapPost(string.Empty, async (CreateTenantRequest request, HttpContext context, ICommandHandler<CreateTenantCommand, TenantDto> handler) =>
            ToResult(await handler.HandleAsync(new CreateTenantCommand(Operator(context), request.Name, request.FirstAdmin), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
        operators.MapGet("{tenantId:guid}", async (Guid tenantId, HttpContext context, IQueryHandler<GetTenantQuery, TenantDto> handler) =>
            ToResult(await handler.HandleAsync(new GetTenantQuery(Operator(context), tenantId), context.RequestAborted).ConfigureAwait(false)));
        operators.MapPatch("{tenantId:guid}", async (Guid tenantId, UpdateTenantRequest request, HttpContext context, ICommandHandler<UpdateTenantCommand, TenantDto> handler) =>
            ToResult(await handler.HandleAsync(new UpdateTenantCommand(Operator(context), tenantId, request.Name, request.Status), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
        operators.MapPost("{tenantId:guid}/members", async (Guid tenantId, AddMemberRequest request, HttpContext context, ICommandHandler<AddMemberCommand, MemberDto> handler) =>
            ToResult(await handler.HandleAsync(new AddMemberCommand(Operator(context), tenantId, request.AccountId, request.Role), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
        MapTenantResources(operators, "{tenantId:guid}", Operator, RouteTenant);

        // ---- Tenant administrators ------------------------------------------------------------------------------------
        var admins = endpoints.MapGroup(TenantRoutes).WithTags("Tenancy (tenant administrators)").RequireAuthorization(tokenPolicy).AddEndpointFilter<TenantAdministratorFilter>();
        admins.MapGet(string.Empty, async (HttpContext context, IQueryHandler<GetTenantQuery, TenantDto> handler) =>
            ToResult(await handler.HandleAsync(new GetTenantQuery(Admin(context), SessionTenant(context)), context.RequestAborted).ConfigureAwait(false)));
        admins.MapPatch(string.Empty, async (UpdateTenantRequest request, HttpContext context, ICommandHandler<UpdateTenantCommand, TenantDto> handler) =>
            ToResult(await handler.HandleAsync(new UpdateTenantCommand(Admin(context), SessionTenant(context), request.Name, request.Status), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
        MapTenantResources(admins, string.Empty, Admin, SessionTenant);

        // ---- Any signed-in user ---------------------------------------------------------------------------------------
        endpoints.MapGet(MembershipsRoute, async (HttpContext context, IQueryHandler<ListMyTenantsQuery, IReadOnlyList<MyTenantDto>> handler) =>
            OwnAccount(context) is { } account
                ? ToResult(await handler.HandleAsync(new ListMyTenantsQuery(account), context.RequestAborted).ConfigureAwait(false))
                : OwnSessionRequired())
            .WithTags("Tenancy").RequireAuthorization(tokenPolicy);
        endpoints.MapPost(AcceptRoute, async (AcceptInvitationRequest request, HttpContext context, ICommandHandler<AcceptInvitationCommand, InvitationPreview> handler) =>
            OwnAccount(context) is { } account
                ? ToResult(await handler.HandleAsync(new AcceptInvitationCommand(account, request.Token), context.RequestAborted).ConfigureAwait(false))
                : OwnSessionRequired())
            .WithTags("Tenancy").RequireAuthorization(tokenPolicy);

        // ---- Products' backends (client credentials with the signup permission) --------------------------------------
        endpoints.MapPost(SignupRoute, async (SignupRequest request, HttpContext context, ICommandHandler<SignupTenantCommand, SignupResult> handler) =>
        {
            var names = Names(context);
            var permission = context.RequestServices.GetRequiredService<IOptions<TenancyOptions>>().Value.SignupPermission;
            if (!IsServiceWithPermission(context, names, permission))
            {
                return TypedResults.Problem(detail: $"Only a service holding {permission} can do this.", statusCode: StatusCodes.Status403Forbidden,
                    extensions: new Dictionary<string, object?> { ["code"] = "not_allowed" });
            }

            var clientId = context.User.FindFirst(names.Subject)?.Value ?? "unknown";
            return ToResult(await handler.HandleAsync(new SignupTenantCommand(clientId, request.Name, request.AdminAccountId, request.EntraDirectoryId), context.RequestAborted).ConfigureAwait(false));
        }).WithTags("Tenancy").RequireAuthorization(tokenPolicy);

        // ---- The invitation page (the sign-in session, not a bearer token) ---------------------------------------------
        InvitationPages.Map(endpoints);
        return endpoints;
    }

    /// <summary>Members, directories and invitations of the tenant <paramref name="tenantOf"/> picks, under <paramref name="prefix"/>.</summary>
    private static void MapTenantResources(RouteGroupBuilder group, string prefix, Func<HttpContext, TenancyActor> actorOf, Func<HttpContext, Guid> tenantOf)
    {
        string Path(string tail) => string.IsNullOrEmpty(prefix) ? tail : $"{prefix}/{tail}";

        group.MapGet(Path("members"), async (HttpContext context, IQueryHandler<ListMembersQuery, IReadOnlyList<MemberDto>> handler) =>
            ToResult(await handler.HandleAsync(new ListMembersQuery(actorOf(context), tenantOf(context)), context.RequestAborted).ConfigureAwait(false)));
        group.MapPut(Path("members/{accountId:guid}"), async (Guid accountId, SetRoleRequest request, HttpContext context, ICommandHandler<SetMemberRoleCommand, MemberDto> handler) =>
            ToResult(await handler.HandleAsync(new SetMemberRoleCommand(actorOf(context), tenantOf(context), accountId, request.Role), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
        group.MapDelete(Path("members/{accountId:guid}"), async (Guid accountId, HttpContext context, ICommandHandler<RemoveMemberCommand> handler) =>
            NoContent(await handler.HandleAsync(new RemoveMemberCommand(actorOf(context), tenantOf(context), accountId), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();

        group.MapGet(Path("directories"), async (HttpContext context, IQueryHandler<ListDirectoriesQuery, IReadOnlyList<DirectoryLinkDto>> handler) =>
            ToResult(await handler.HandleAsync(new ListDirectoriesQuery(actorOf(context), tenantOf(context)), context.RequestAborted).ConfigureAwait(false)));
        group.MapPost(Path("directories"), async (LinkDirectoryRequest request, HttpContext context, ICommandHandler<LinkDirectoryCommand, DirectoryLinkDto> handler) =>
            ToResult(await handler.HandleAsync(new LinkDirectoryCommand(actorOf(context), tenantOf(context), request.EntraDirectoryId), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
        group.MapDelete(Path("directories/{directoryId:guid}"), async (Guid directoryId, HttpContext context, ICommandHandler<UnlinkDirectoryCommand> handler) =>
            NoContent(await handler.HandleAsync(new UnlinkDirectoryCommand(actorOf(context), tenantOf(context), directoryId), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();

        group.MapGet(Path("invitations"), async (HttpContext context, IQueryHandler<ListInvitationsQuery, IReadOnlyList<InvitationDto>> handler) =>
            ToResult(await handler.HandleAsync(new ListInvitationsQuery(actorOf(context), tenantOf(context)), context.RequestAborted).ConfigureAwait(false)));
        group.MapPost(Path("invitations"), async (CreateInvitationRequest request, HttpContext context, ICommandHandler<CreateInvitationCommand, CreatedInvitation> handler) =>
        {
            var created = await handler.HandleAsync(new CreateInvitationCommand(actorOf(context), tenantOf(context), request.Email, request.Role), context.RequestAborted).ConfigureAwait(false);
            return created.IsSuccess
                ? TypedResults.Ok(new InvitationLinkDto(InvitationPages.LinkFor(context, created.Value.Token), created.Value.Invitation))
                : Problem(created.Error);
        }).AddEndpointFilter<StepUpFilter>();
        group.MapDelete(Path("invitations/{invitationId:guid}"), async (Guid invitationId, HttpContext context, ICommandHandler<RevokeInvitationCommand> handler) =>
            NoContent(await handler.HandleAsync(new RevokeInvitationCommand(actorOf(context), tenantOf(context), invitationId), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
    }

    private static TenancyActor Operator(HttpContext context) => new(AccessContextReader.Read(context.User, Names(context)).UserId!.Value, IsOperator: true);

    private static TenancyActor Admin(HttpContext context) => new(AccessContextReader.Read(context.User, Names(context)).UserId!.Value, IsOperator: false);

    private static Guid RouteTenant(HttpContext context) => Guid.Parse((string)context.Request.RouteValues["tenantId"]!, System.Globalization.CultureInfo.InvariantCulture);

    private static Guid SessionTenant(HttpContext context) => AccessContextReader.Read(context.User, Names(context)).TenantId!.Value;

    private static Guid? OwnAccount(HttpContext context)
    {
        var names = Names(context);
        return AccessContextReader.IsOwnSession(context.User, names) ? AccessContextReader.Read(context.User, names).UserId : null;
    }

    internal static ClaimNames Names(HttpContext context) => context.RequestServices.GetService<ClaimNames>() ?? ClaimNames.Default;

    internal static bool IsServiceWithPermission(HttpContext context, ClaimNames names, string permission) =>
        AccessContextReader.Read(context.User, names).Level == AccessLevel.Service
        && AccessContextReader.ValuesOf(context.User, names.ServicePermission).Any(held =>
            held == "*"
            || string.Equals(held, permission, StringComparison.OrdinalIgnoreCase)
            || (held.EndsWith(".*", StringComparison.Ordinal) && permission.StartsWith(held[..^1], StringComparison.OrdinalIgnoreCase)));

    private static IResult OwnSessionRequired() =>
        TypedResults.Problem(detail: "Only a user in their own session can do this.", statusCode: StatusCodes.Status403Forbidden,
            extensions: new Dictionary<string, object?> { ["code"] = "home_session_required" });

    private static IResult ToResult<T>(Result<T> result) => result.IsSuccess ? TypedResults.Ok(result.Value) : Problem(result.Error);

    private static IResult NoContent(Result result) => result.IsSuccess ? TypedResults.NoContent() : Problem(result.Error);

    internal static IResult Problem(Error error) =>
        TypedResults.Problem(
            detail: error.Message,
            statusCode: error.Type switch
            {
                ErrorType.NotFound => StatusCodes.Status404NotFound,
                ErrorType.Conflict => StatusCodes.Status409Conflict,
                ErrorType.Forbidden => StatusCodes.Status403Forbidden,
                ErrorType.Unavailable => StatusCodes.Status503ServiceUnavailable,
                _ => StatusCodes.Status400BadRequest,
            },
            extensions: new Dictionary<string, object?> { ["code"] = error.Code });
}

/// <summary>Platform operators in their own session (<see cref="TenancyOptions.OperatorPolicy"/>).</summary>
internal sealed class OperatorFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var http = context.HttpContext;
        var names = TenancyEndpointRouteBuilderExtensions.Names(http);
        var policy = http.RequestServices.GetRequiredService<IOptions<TenancyOptions>>().Value.OperatorPolicy;
        var defined = await http.RequestServices.GetRequiredService<IAuthorizationPolicyProvider>().GetPolicyAsync(policy).ConfigureAwait(false);
        if (!AccessContextReader.IsOwnSession(http.User, names) || AccessContextReader.Read(http.User, names).UserId is null || defined is null
            || !(await http.RequestServices.GetRequiredService<IAuthorizationService>().AuthorizeAsync(http.User, defined).ConfigureAwait(false)).Succeeded)
        {
            return TypedResults.Problem(detail: "Only a platform operator in their own session can do this.", statusCode: StatusCodes.Status403Forbidden,
                extensions: new Dictionary<string, object?> { ["code"] = "not_allowed" });
        }

        return await next(context).ConfigureAwait(false);
    }
}

/// <summary>An administrator of the session's tenant, in their own session (<see cref="TenancyOptions.ManagePolicy"/>).</summary>
internal sealed class TenantAdministratorFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var http = context.HttpContext;
        var names = TenancyEndpointRouteBuilderExtensions.Names(http);
        var access = AccessContextReader.Read(http.User, names);
        if (!AccessContextReader.IsOwnSession(http.User, names) || access.UserId is null || access.TenantId is null)
        {
            return TypedResults.Problem(detail: "Only a tenant administrator in their own session can do this.", statusCode: StatusCodes.Status403Forbidden,
                extensions: new Dictionary<string, object?> { ["code"] = "home_session_required" });
        }

        var policy = http.RequestServices.GetRequiredService<IOptions<TenancyOptions>>().Value.ManagePolicy;
        var defined = await http.RequestServices.GetRequiredService<IAuthorizationPolicyProvider>().GetPolicyAsync(policy).ConfigureAwait(false);
        if (defined is null || !(await http.RequestServices.GetRequiredService<IAuthorizationService>().AuthorizeAsync(http.User, defined).ConfigureAwait(false)).Succeeded)
        {
            return TypedResults.Problem(detail: "You are not an administrator of this tenant.", statusCode: StatusCodes.Status403Forbidden,
                extensions: new Dictionary<string, object?> { ["code"] = "not_allowed" });
        }

        return await next(context).ConfigureAwait(false);
    }
}

/// <summary>Changes need a recent multi-factor sign-in (RFC 9470 challenge), as everywhere in the token server's own APIs.</summary>
internal sealed class StepUpFilter : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var http = context.HttpContext;
        if (AccessContextReader.IsSteppedUp(http.User, TenancyEndpointRouteBuilderExtensions.Names(http)))
        {
            return next(context);
        }

        http.Response.Headers.WWWAuthenticate =
            "Bearer error=\"insufficient_user_authentication\", error_description=\"A multi-factor sign-in is required.\"";
        return ValueTask.FromResult<object?>(TypedResults.Problem(detail: "This change requires a multi-factor sign-in (step-up).", statusCode: StatusCodes.Status403Forbidden,
            extensions: new Dictionary<string, object?> { ["code"] = "step_up_required" }));
    }
}

/// <summary>
/// <c>GET /invitations/{token}</c>: sign in (any way the server offers), see the tenant and the role, accept with the form;
/// <c>POST</c> (antiforgery) accepts. Uses the sign-in session, like the login pages, so the link works from any product.
/// </summary>
internal static class InvitationPages
{
    private const string Policy =
        "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'";

    public static Uri LinkFor(HttpContext context, string token)
    {
        var issuer = context.RequestServices.GetRequiredService<IOptions<TokenServerOptions>>().Value.Issuer
            ?? new Uri($"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/");
        return new Uri(issuer, $"{TenancyEndpointRouteBuilderExtensions.InvitationPage}/{Uri.EscapeDataString(token)}");
    }

    public static void Map(IEndpointRouteBuilder endpoints)
    {
        var page = endpoints.MapGroup(TenancyEndpointRouteBuilderExtensions.InvitationPage).AllowAnonymous().ExcludeFromDescription();

        page.MapGet("{token}", async (string token, HttpContext context, IAntiforgery antiforgery, IQueryHandler<PreviewInvitationQuery, InvitationPreview> preview) =>
        {
            if (await SignedInAccountAsync(context).ConfigureAwait(false) is null)
            {
                return Results.Challenge(new AuthenticationProperties { RedirectUri = context.Request.Path }, [SignInScheme(context)]);
            }

            var found = await preview.HandleAsync(new PreviewInvitationQuery(token), context.RequestAborted).ConfigureAwait(false);
            if (!found.IsSuccess)
            {
                return Html(context, "Invitation", $"<p class=\"jo-error\" role=\"alert\">{Encode(found.Error.Message)}</p>", StatusCodes.Status404NotFound);
            }

            var tokens = antiforgery.GetAndStoreTokens(context);
            var invitation = found.Value;
            var role = invitation.Role == "Admin" ? "an administrator" : "a member";
            return Html(context, "Invitation", $"""
                <p>You're invited to join <strong>{Encode(invitation.TenantName)}</strong> as {role}.</p>
                <form method="post" action="/{TenancyEndpointRouteBuilderExtensions.InvitationPage}/{Encode(Uri.EscapeDataString(token))}">
                  <input type="hidden" name="{Encode(tokens.FormFieldName)}" value="{Encode(tokens.RequestToken ?? string.Empty)}" />
                  <button type="submit">Join {Encode(invitation.TenantName)}</button>
                </form>
                """);
        });

        page.MapPost("{token}", async (string token, HttpContext context, IAntiforgery antiforgery, ICommandHandler<AcceptInvitationCommand, InvitationPreview> accept) =>
        {
            if (!await antiforgery.IsRequestValidAsync(context).ConfigureAwait(false))
            {
                return Results.BadRequest();
            }

            if (await SignedInAccountAsync(context).ConfigureAwait(false) is not { } account)
            {
                return Results.Challenge(new AuthenticationProperties { RedirectUri = context.Request.Path }, [SignInScheme(context)]);
            }

            var accepted = await accept.HandleAsync(new AcceptInvitationCommand(account, token), context.RequestAborted).ConfigureAwait(false);
            return accepted.IsSuccess
                ? Html(context, "Invitation accepted", $"<p>You're now {(accepted.Value.Role == "Admin" ? "an administrator" : "a member")} of <strong>{Encode(accepted.Value.TenantName)}</strong>. You can close this page and continue in the application.</p>")
                : Html(context, "Invitation", $"<p class=\"jo-error\" role=\"alert\">{Encode(accepted.Error.Message)}</p>", StatusCodes.Status404NotFound);
        }).DisableAntiforgery();
    }

    private static string SignInScheme(HttpContext context) =>
        context.RequestServices.GetRequiredService<IOptions<TokenServerOptions>>().Value.SignInScheme;

    private static async Task<Guid?> SignedInAccountAsync(HttpContext context)
    {
        var names = TenancyEndpointRouteBuilderExtensions.Names(context);
        var signedIn = await context.AuthenticateAsync(SignInScheme(context)).ConfigureAwait(false);
        return signedIn.Succeeded && Guid.TryParse(signedIn.Principal?.FindFirst(names.Subject)?.Value, out var account) ? account : null;
    }

    private static string Encode(string value) => HtmlEncoder.Default.Encode(value);

    private static IResult Html(HttpContext context, string title, string body, int status = StatusCodes.Status200OK)
    {
        context.Response.Headers.ContentSecurityPolicy = Policy;
        context.Response.Headers.CacheControl = "no-store";
        return Results.Content($"""
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8" />
              <meta name="viewport" content="width=device-width, initial-scale=1" />
              <title>{Encode(title)}</title>
              <link rel="stylesheet" href="/_content/JeffOps.Authentication.UI/jeffops-login.css" />
            </head>
            <body>
              <main class="jo-login">
                <h1>{Encode(title)}</h1>
                {body}
              </main>
            </body>
            </html>
            """, "text/html; charset=utf-8", System.Text.Encoding.UTF8, status);
    }
}

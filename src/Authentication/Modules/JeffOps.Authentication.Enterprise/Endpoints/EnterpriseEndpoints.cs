using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Enterprise.Application;
using JeffOps.Authentication.Enterprise.Application.Features.Domains;
using JeffOps.Authentication.Enterprise.Application.Features.Providers;
using JeffOps.Authentication.Enterprise.Application.Features.ScimTokens;
using JeffOps.Authentication.Enterprise.Application.Features.Sso;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Enterprise.Endpoints;

public sealed record ClaimDomainRequest(string Domain);

public sealed record SetSsoPolicyRequest(string? Provider, bool SsoOnly);

public sealed record CreateScimTokenRequest(string Name);

public sealed record SetCustomProvidersRequest(bool Allowed);

public static class EnterpriseEndpointRouteBuilderExtensions
{
    public const string DomainRoutes = "enterprise/domains";
    public const string SsoRoute = "enterprise/sso";
    public const string ScimTokenRoutes = "enterprise/scim-tokens";

    public const string ProviderRoutes = "enterprise/providers";

    public const string OidcProviderRoutes = "enterprise/oidc-providers";

    public const string OperatorProviderRoute = "enterprise/admin/tenants/{tenantId:guid}/custom-providers";

    /// <summary>Operators take a verified domain away from the tenant holding it (POST).</summary>
    public const string OperatorRevokeDomainRoute = "enterprise/admin/domains/{domain}/revoke";

    /// <summary>
    /// Maps tenant administration of verified domains (<c>enterprise/domains</c>: list, claim, verify, remove), the
    /// single sign-on policy (<c>enterprise/sso</c>: get, set) and SCIM tokens (<c>enterprise/scim-tokens</c>: list, create,
    /// revoke) for the caller's own tenant. Callers need the host's
    /// <see cref="EnterpriseOptions.ManagePolicy"/>, their own (non-impersonated, non-delegated) session, and step-up for changes.
    /// </summary>
    public static IEndpointRouteBuilder MapJeffOpsEnterprise(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        // Only access tokens issued for the token server's own APIs (the account audience), never a token meant for an API.
        const string tokenPolicy = JeffOps.Authentication.Application.AccountApi.PolicyName;

        var root = endpoints.MapGroup(string.Empty).WithTags("Enterprise").RequireAuthorization(tokenPolicy).AddEndpointFilter<TenantAdministratorFilter>();

        root.MapGet(DomainRoutes, async (HttpContext context, IQueryHandler<ListDomainsQuery, IReadOnlyList<TenantDomainDto>> handler) =>
            ToResult(await handler.HandleAsync(new ListDomainsQuery(Caller(context)), context.RequestAborted).ConfigureAwait(false)));
        root.MapPost(DomainRoutes, async (ClaimDomainRequest request, HttpContext context, ICommandHandler<ClaimDomainCommand, TenantDomainDto> handler) =>
            ToResult(await handler.HandleAsync(new ClaimDomainCommand(Caller(context), request.Domain), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
        root.MapPost(DomainRoutes + "/{domainId:guid}/verify", async (Guid domainId, HttpContext context, ICommandHandler<VerifyDomainCommand, TenantDomainDto> handler) =>
            ToResult(await handler.HandleAsync(new VerifyDomainCommand(Caller(context), domainId), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
        root.MapDelete(DomainRoutes + "/{domainId:guid}", async (Guid domainId, HttpContext context, ICommandHandler<RemoveDomainCommand> handler) =>
        {
            var result = await handler.HandleAsync(new RemoveDomainCommand(Caller(context), domainId), context.RequestAborted).ConfigureAwait(false);
            return result.IsSuccess ? TypedResults.NoContent() : Problem(result.Error);
        }).AddEndpointFilter<StepUpFilter>();

        root.MapGet(SsoRoute, async (HttpContext context, IQueryHandler<GetSsoPolicyQuery, SsoPolicyDto> handler) =>
            ToResult(await handler.HandleAsync(new GetSsoPolicyQuery(Caller(context)), context.RequestAborted).ConfigureAwait(false)));
        root.MapPut(SsoRoute, async (
            SetSsoPolicyRequest request,
            HttpContext context,
            IEnumerable<IExternalIdentityMapper> mappers,
            ITenantIdentityProviderRepository own,
            ITenantOidcProviderRepository ownOidc,
            ICommandHandler<SetSsoPolicyCommand, SsoPolicyDto> handler) =>
        {
            // The server's providers, and this tenant's own (never another tenant's).
            var tenantId = Caller(context).TenantId;
            var known = mappers.SelectMany(mapper => mapper.Providers).Select(provider => provider.Name)
                .Concat((await own.ListForTenantAsync(tenantId, context.RequestAborted).ConfigureAwait(false)).Select(provider => provider.Name))
                .Concat((await ownOidc.ListForTenantAsync(tenantId, context.RequestAborted).ConfigureAwait(false)).Select(provider => provider.Name))
                .ToList();
            return ToResult(await handler.HandleAsync(new SetSsoPolicyCommand(Caller(context), request.Provider, request.SsoOnly, known), context.RequestAborted).ConfigureAwait(false));
        }).AddEndpointFilter<StepUpFilter>();

        root.MapGet(ScimTokenRoutes, async (HttpContext context, IQueryHandler<ListScimTokensQuery, IReadOnlyList<ScimTokenDto>> handler) =>
            ToResult(await handler.HandleAsync(new ListScimTokensQuery(Caller(context)), context.RequestAborted).ConfigureAwait(false)));
        root.MapPost(ScimTokenRoutes, async (CreateScimTokenRequest request, HttpContext context, ICommandHandler<CreateScimTokenCommand, CreatedScimToken> handler) =>
            ToResult(await handler.HandleAsync(new CreateScimTokenCommand(Caller(context), request.Name), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>()
            .AddEndpointFilter(async (context, next) =>
            {
                // A SCIM token controls group membership (and so group roles): it needs more than tenant administration. A policy
                // the host never defined refuses, rather than failing the request.
                var services = context.HttpContext.RequestServices;
                if (services.GetRequiredService<IOptions<EnterpriseOptions>>().Value.ScimTokenPolicy is { } policy)
                {
                    var defined = await services.GetRequiredService<IAuthorizationPolicyProvider>().GetPolicyAsync(policy).ConfigureAwait(false);
                    if (defined is null
                        || !(await services.GetRequiredService<IAuthorizationService>().AuthorizeAsync(context.HttpContext.User, defined).ConfigureAwait(false)).Succeeded)
                    {
                        return TypedResults.Problem(
                            detail: defined is null ? $"SCIM tokens need the '{policy}' policy, which this server doesn't define." : "You are not allowed to create SCIM tokens.",
                            statusCode: StatusCodes.Status403Forbidden,
                            extensions: new Dictionary<string, object?> { ["code"] = "not_allowed" });
                    }
                }

                return await next(context).ConfigureAwait(false);
            });
        root.MapDelete(ScimTokenRoutes + "/{tokenId:guid}", async (Guid tokenId, HttpContext context, ICommandHandler<RevokeScimTokenCommand> handler) =>
        {
            var result = await handler.HandleAsync(new RevokeScimTokenCommand(Caller(context), tokenId), context.RequestAborted).ConfigureAwait(false);
            return result.IsSuccess ? TypedResults.NoContent() : Problem(result.Error);
        }).AddEndpointFilter<StepUpFilter>();

        root.MapGet(ProviderRoutes, async (HttpContext context, IQueryHandler<ListTenantProvidersQuery, IReadOnlyList<TenantProviderDto>> handler) =>
            ToResult(await handler.HandleAsync(new ListTenantProvidersQuery(Caller(context)), context.RequestAborted).ConfigureAwait(false)));
        root.MapPost(ProviderRoutes, async (TenantProviderData request, HttpContext context, ICommandHandler<SaveTenantProviderCommand, TenantProviderDto> handler) =>
            ToResult(await handler.HandleAsync(new SaveTenantProviderCommand(Caller(context), null, request), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
        root.MapPut(ProviderRoutes + "/{providerId:guid}", async (Guid providerId, TenantProviderData request, HttpContext context, ICommandHandler<SaveTenantProviderCommand, TenantProviderDto> handler) =>
            ToResult(await handler.HandleAsync(new SaveTenantProviderCommand(Caller(context), providerId, request), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
        root.MapDelete(ProviderRoutes + "/{providerId:guid}", async (Guid providerId, HttpContext context, ICommandHandler<DeleteTenantProviderCommand> handler) =>
        {
            var result = await handler.HandleAsync(new DeleteTenantProviderCommand(Caller(context), providerId), context.RequestAborted).ConfigureAwait(false);
            return result.IsSuccess ? TypedResults.NoContent() : Problem(result.Error);
        }).AddEndpointFilter<StepUpFilter>();

        root.MapGet(OidcProviderRoutes, async (HttpContext context, IQueryHandler<ListTenantOidcProvidersQuery, IReadOnlyList<TenantOidcProviderDto>> handler) =>
            ToResult(await handler.HandleAsync(new ListTenantOidcProvidersQuery(Caller(context)), context.RequestAborted).ConfigureAwait(false)));
        root.MapPost(OidcProviderRoutes, async (TenantOidcProviderData request, HttpContext context, ICommandHandler<SaveTenantOidcProviderCommand, TenantOidcProviderDto> handler) =>
            ToResult(await handler.HandleAsync(new SaveTenantOidcProviderCommand(Caller(context), null, request), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
        root.MapPut(OidcProviderRoutes + "/{providerId:guid}", async (Guid providerId, TenantOidcProviderData request, HttpContext context, ICommandHandler<SaveTenantOidcProviderCommand, TenantOidcProviderDto> handler) =>
            ToResult(await handler.HandleAsync(new SaveTenantOidcProviderCommand(Caller(context), providerId, request), context.RequestAborted).ConfigureAwait(false)))
            .AddEndpointFilter<StepUpFilter>();
        root.MapDelete(OidcProviderRoutes + "/{providerId:guid}", async (Guid providerId, HttpContext context, ICommandHandler<DeleteTenantOidcProviderCommand> handler) =>
        {
            var result = await handler.HandleAsync(new DeleteTenantOidcProviderCommand(Caller(context), providerId), context.RequestAborted).ConfigureAwait(false);
            return result.IsSuccess ? TypedResults.NoContent() : Problem(result.Error);
        }).AddEndpointFilter<StepUpFilter>();

        // Platform operators: which tenants may register their own identity providers.
        endpoints.MapPut(OperatorProviderRoute, async (Guid tenantId, SetCustomProvidersRequest request, HttpContext context, ICommandHandler<SetCustomProvidersAllowedCommand> handler) =>
        {
            var operatorId = AccessContextReader.Read(context.User, Names(context)).UserId!.Value;
            var result = await handler.HandleAsync(new SetCustomProvidersAllowedCommand(operatorId, tenantId, request.Allowed), context.RequestAborted).ConfigureAwait(false);
            return result.IsSuccess ? TypedResults.NoContent() : Problem(result.Error);
        })
            .WithTags("Enterprise")
            .RequireAuthorization(tokenPolicy)
            .AddEndpointFilter<OperatorFilter>()
            .AddEndpointFilter<StepUpFilter>();

        // Platform operators: take a verified domain away from a tenant (it changed hands, or was claimed in error).
        endpoints.MapPost(OperatorRevokeDomainRoute, async (string domain, HttpContext context, ICommandHandler<RevokeDomainCommand> handler) =>
        {
            var operatorId = AccessContextReader.Read(context.User, Names(context)).UserId!.Value;
            var result = await handler.HandleAsync(new RevokeDomainCommand(operatorId, domain), context.RequestAborted).ConfigureAwait(false);
            return result.IsSuccess ? TypedResults.NoContent() : Problem(result.Error);
        })
            .WithTags("Enterprise")
            .RequireAuthorization(tokenPolicy)
            .AddEndpointFilter<OperatorFilter>()
            .AddEndpointFilter<StepUpFilter>();

        return endpoints;
    }

    private static EnterpriseCaller Caller(HttpContext context)
    {
        var access = AccessContextReader.Read(context.User, Names(context));
        return new EnterpriseCaller(access.UserId!.Value, access.TenantId!.Value);
    }

    internal static ClaimNames Names(HttpContext context) => context.RequestServices.GetService<ClaimNames>() ?? ClaimNames.Default;

    private static IResult ToResult<T>(Result<T> result) => result.IsSuccess ? TypedResults.Ok(result.Value) : Problem(result.Error);

    private static IResult Problem(Error error) =>
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

/// <summary>A tenant administrator in their own session: a user with a tenant, not impersonating or acting elsewhere, passing the manage policy.</summary>
internal sealed class TenantAdministratorFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var http = context.HttpContext;
        var names = EnterpriseEndpointRouteBuilderExtensions.Names(http);
        var access = AccessContextReader.Read(http.User, names);
        var ownSession = AccessContextReader.IsOwnSession(http.User, names) && access.TenantId is not null;
        if (!ownSession)
        {
            return TypedResults.Problem(detail: "Only a tenant administrator in their own session can do this.", statusCode: StatusCodes.Status403Forbidden,
                extensions: new Dictionary<string, object?> { ["code"] = "home_session_required" });
        }

        var policy = http.RequestServices.GetRequiredService<IOptions<EnterpriseOptions>>().Value.ManagePolicy;
        var authorized = await http.RequestServices.GetRequiredService<IAuthorizationService>().AuthorizeAsync(http.User, policy).ConfigureAwait(false);
        if (!authorized.Succeeded)
        {
            return TypedResults.Problem(detail: "You are not allowed to manage this tenant's sign-in settings.", statusCode: StatusCodes.Status403Forbidden,
                extensions: new Dictionary<string, object?> { ["code"] = "not_allowed" });
        }

        return await next(context).ConfigureAwait(false);
    }
}

/// <summary>Platform operators in their own session, holding <see cref="EnterpriseOptions.OperatorPolicy"/>.</summary>
internal sealed class OperatorFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var http = context.HttpContext;
        var names = EnterpriseEndpointRouteBuilderExtensions.Names(http);
        var access = AccessContextReader.Read(http.User, names);
        var ownSession = AccessContextReader.IsOwnSession(http.User, names) && access.UserId is not null;
        // A host that doesn't define the operator policy has no operators (fail closed).
        var policy = http.RequestServices.GetRequiredService<IOptions<EnterpriseOptions>>().Value.OperatorPolicy;
        var defined = await http.RequestServices.GetRequiredService<IAuthorizationPolicyProvider>().GetPolicyAsync(policy).ConfigureAwait(false);
        if (!ownSession || defined is null
            || !(await http.RequestServices.GetRequiredService<IAuthorizationService>().AuthorizeAsync(http.User, defined).ConfigureAwait(false)).Succeeded)
        {
            return TypedResults.Problem(detail: "Only a platform operator in their own session can do this.", statusCode: StatusCodes.Status403Forbidden,
                extensions: new Dictionary<string, object?> { ["code"] = "not_allowed" });
        }

        return await next(context).ConfigureAwait(false);
    }
}

/// <summary>Changes need a stepped-up session (RFC 9470 challenge).</summary>
internal sealed class StepUpFilter : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var http = context.HttpContext;
        if (AccessContextReader.IsSteppedUp(http.User, EnterpriseEndpointRouteBuilderExtensions.Names(http)))
        {
            return next(context);
        }

        http.Response.Headers.WWWAuthenticate =
            "Bearer error=\"insufficient_user_authentication\", error_description=\"A multi-factor sign-in is required.\"";
        return ValueTask.FromResult<object?>(TypedResults.Problem(detail: "This change requires a multi-factor sign-in (step-up).", statusCode: StatusCodes.Status403Forbidden,
            extensions: new Dictionary<string, object?> { ["code"] = "step_up_required" }));
    }
}

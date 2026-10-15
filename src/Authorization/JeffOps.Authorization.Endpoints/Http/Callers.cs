using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authorization.Application;
using JeffOps.Authorization.Application.Management;
using JeffOps.Authorization.Domain.Decisions;
using JeffOps.Authorization.Domain.Permissions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace JeffOps.Authorization.Endpoints.Http;

/// <summary>Reads the management caller from the validated token.</summary>
internal static class Callers
{
    public static ManagementCaller From(ClaimsPrincipal user, ClaimNames names)
    {
        var access = AccessContextReader.Read(user, names);
        var isService = access.Level == AccessLevel.Service;
        return new ManagementCaller(
            access.UserId,
            IsRoot: access.IsRoot,
            IsService: isService,
            ServiceName: isService ? user.FindFirst(names.Subject)?.Value : null,
            access.TenantId,
            access.ActingTenantId)
        {
            PatCeiling = AccessContextReader.ValuesOf(user, names.PatCeiling),
            ServicePermissions = isService ? AccessContextReader.ValuesOf(user, names.ServicePermission) : [],
        };
    }

    public static ManagementCaller Caller(this HttpContext context) =>
        From(context.User, context.RequestServices.GetService<ClaimNames>() ?? ClaimNames.Default);
}

/// <summary>
/// Guards management changes: never under impersonation, and (by default) only after a stepped-up sign-in for interactive
/// users, answered with an RFC 9470 challenge.
/// </summary>
internal sealed class ManagementChangeFilter : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var http = context.HttpContext;
        var names = http.RequestServices.GetService<ClaimNames>() ?? ClaimNames.Default;
        var options = http.RequestServices.GetRequiredService<IOptions<ManagementOptions>>().Value;

        if (AccessContextReader.IsImpersonation(http.User, names))
        {
            return ValueTask.FromResult<object?>(Forbidden(AuthorizationCodes.ImpersonationNotAllowed, "Management changes are not available while impersonating another user."));
        }

        if (options.RequireStepUpForChanges && AccessContextReader.IsInteractiveUser(http.User, names) && !AccessContextReader.IsSteppedUp(http.User, names))
        {
            http.Response.Headers.WWWAuthenticate =
                "Bearer error=\"insufficient_user_authentication\", error_description=\"A multi-factor sign-in is required.\"";
            return ValueTask.FromResult<object?>(Forbidden(AuthorizationCodes.StepUpRequired, "Management changes require a multi-factor sign-in (step-up)."));
        }

        return next(context);
    }

    private static IResult Forbidden(string code, string detail) =>
        TypedResults.Problem(detail: detail, statusCode: StatusCodes.Status403Forbidden, extensions: new Dictionary<string, object?> { ["code"] = code });
}

/// <summary>The read API serves resource services (a service principal granted the read permission) and platform administrators.</summary>
internal sealed class ReadApiFilter : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var http = context.HttpContext;
        var caller = http.Caller();
        var permission = http.RequestServices.GetRequiredService<IOptions<ManagementOptions>>().Value.Permissions.ReadApi;

        return caller.IsRoot || (caller.IsService && Permission.GrantsAny(caller.ServicePermissions, permission))
            ? next(context)
            : ValueTask.FromResult<object?>(TypedResults.Problem(
                detail: $"The authorization read API needs a service granted {permission}.",
                statusCode: StatusCodes.Status403Forbidden,
                extensions: new Dictionary<string, object?> { ["code"] = ManagementErrors.MissingPermission }));
    }
}

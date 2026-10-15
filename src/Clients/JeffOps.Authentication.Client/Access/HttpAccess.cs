using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Client.Access;

/// <summary>The caller of the current HTTP request.</summary>
internal sealed class HttpCurrentUser(IHttpContextAccessor httpContextAccessor, ClaimNames names) : ICurrentUser
{
    private System.Security.Claims.ClaimsPrincipal? User => httpContextAccessor.HttpContext?.User;

    public bool IsAuthenticated => User?.Identity?.IsAuthenticated == true;

    public Guid? UserId => IsAuthenticated ? AccessContextReader.Read(User, names).UserId : null;

    public string? Email => IsAuthenticated ? User!.FindFirst(names.Email)?.Value : null;

    public string? DisplayName => IsAuthenticated ? User!.FindFirst(names.Name)?.Value : null;
}

/// <summary>
/// The access context of the current HTTP request: claims, plus — for service tokens, when enabled — the tenant carried
/// by trusted internal headers (<see cref="ServiceTokenTenantScopingOptions"/>). Users are never scoped by headers.
/// </summary>
internal sealed class HttpAccessContextAccessor(
    IHttpContextAccessor httpContextAccessor,
    ClaimNames names,
    IOptions<AuthenticationClientOptions> options) : IAccessContextAccessor
{
    public AccessContext GetAccessContext()
    {
        var http = httpContextAccessor.HttpContext;
        var context = AccessContextReader.Read(http?.User, names);
        if (http is null || context.ActingTenantId is not null || !HeaderScopingEnabled(context.Level))
        {
            return context;
        }

        var scoping = options.Value.ServiceTokenTenantScoping;
        var headerTenant = TenantFrom(http, scoping.ActingTenantHeader) ?? TenantFrom(http, scoping.TenantHeader);
        return headerTenant is null ? context : context with { ActingTenantId = headerTenant };
    }

    private bool HeaderScopingEnabled(AccessLevel level) => level switch
    {
        AccessLevel.Root => options.Value.ServiceTokenTenantScoping.TrustForRootTokens,
        AccessLevel.Service => options.Value.ServiceTokenTenantScoping.TrustForServiceTokens,
        _ => false,
    };

    private static Guid? TenantFrom(HttpContext http, string header) =>
        http.Request.Headers.TryGetValue(header, out var value) && value.Count == 1 && Guid.TryParse(value[0], out var tenant)
            ? tenant
            : null;
}

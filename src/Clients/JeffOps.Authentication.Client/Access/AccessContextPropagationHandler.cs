using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Client.Access;

/// <summary>
/// Propagates the current caller's tenant on service-to-service calls made on their behalf, in the headers a callee
/// trusts only from service tokens (<see cref="ServiceTokenTenantScopingOptions"/>). Adds nothing outside a request.
/// </summary>
public sealed class AccessContextPropagationHandler(
    IHttpContextAccessor httpContextAccessor,
    ClaimNames names,
    IOptions<AuthenticationClientOptions> options) : DelegatingHandler
{
    /// <inheritdoc />
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var context = AccessContextReader.Read(httpContextAccessor.HttpContext?.User, names);
        var headers = options.Value.ServiceTokenTenantScoping;

        if (context.TenantId is { } tenant && !request.Headers.Contains(headers.TenantHeader))
        {
            request.Headers.Add(headers.TenantHeader, tenant.ToString());
        }

        if (context.ActingTenantId is { } acting && !request.Headers.Contains(headers.ActingTenantHeader))
        {
            request.Headers.Add(headers.ActingTenantHeader, acting.ToString());
        }

        return base.SendAsync(request, cancellationToken);
    }
}

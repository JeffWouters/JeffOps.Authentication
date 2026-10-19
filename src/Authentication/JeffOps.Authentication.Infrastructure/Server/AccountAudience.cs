using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// Requires the access token to be issued for <see cref="TokenServerOptions.AccountAudience"/> (see <see cref="AccountApi"/>),
/// in a sign-in session that hasn't ended: after signing out, the session's access tokens no longer reach these APIs.
/// </summary>
internal sealed class AccountAudienceRequirement : IAuthorizationRequirement;

internal sealed class AccountAudienceHandler(IOptions<TokenServerOptions> options, ClaimNames names) : AuthorizationHandler<AccountAudienceRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AccountAudienceRequirement requirement)
    {
        var audience = options.Value.AccountAudience;
        if (!context.User.FindAll(Claims.Audience).Any(claim => string.Equals(claim.Value, audience, StringComparison.Ordinal)))
        {
            return;
        }

        if (context.User.FindFirst(names.SessionId)?.Value is { Length: > 0 } session
            && context.Resource is HttpContext http
            && await http.RequestServices.GetRequiredService<IEndedSessions>().IsEndedAsync(session, http.RequestAborted).ConfigureAwait(false))
        {
            return;
        }

        context.Succeed(requirement);
    }
}

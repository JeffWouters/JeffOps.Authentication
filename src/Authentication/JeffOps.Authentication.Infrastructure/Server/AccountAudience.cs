using JeffOps.Authentication.Application;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>Requires the access token to be issued for <see cref="TokenServerOptions.AccountAudience"/> (see <see cref="AccountApi"/>).</summary>
internal sealed class AccountAudienceRequirement : IAuthorizationRequirement;

internal sealed class AccountAudienceHandler(IOptions<TokenServerOptions> options) : AuthorizationHandler<AccountAudienceRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AccountAudienceRequirement requirement)
    {
        var audience = options.Value.AccountAudience;
        if (context.User.FindAll(Claims.Audience).Any(claim => string.Equals(claim.Value, audience, StringComparison.Ordinal)))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

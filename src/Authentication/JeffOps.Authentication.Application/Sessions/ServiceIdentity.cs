using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Application.Sessions;

/// <summary>
/// The identity of a service principal: level <see cref="AccessLevel.Service"/> and one permission claim per grant configured
/// for the client. Shared by every grant that issues service tokens; none of them can produce a Root token (docs/DESIGN.md §16).
/// </summary>
public sealed class ServiceIdentity(ClaimNames names, IOptions<TokenServerOptions> options)
{
    public Result<IssuedIdentity> For(string clientId, IReadOnlyCollection<string> scopes)
    {
        var client = options.Value.Clients.FirstOrDefault(candidate => string.Equals(candidate.ClientId, clientId, StringComparison.Ordinal));
        if (client is null)
        {
            return Error.Unauthorized(GrantErrors.InvalidGrant, "This client is not configured for service tokens.");
        }

        var claims = new List<Claim>
        {
            new(names.Subject, client.ClientId),
            new(names.Name, client.DisplayName ?? client.ClientId),
            new(names.Level, nameof(AccessLevel.Service)),
        };
        claims.AddRange(client.ServicePermissions
            .Where(permission => !string.IsNullOrWhiteSpace(permission))
            .Select(permission => permission.Trim())
            .Distinct(StringComparer.Ordinal)
            .Select(permission => new Claim(names.ServicePermission, permission)));

        return new IssuedIdentity(client.ClientId, claims, scopes) { AllowRefresh = false };
    }
}

using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Application.Features.Grants.ClientCredentials;

/// <summary>A service authenticating as itself. The protocol layer has already authenticated the client.</summary>
public sealed record ClientCredentialsCommand(string ClientId, IReadOnlyCollection<string> Scopes);

/// <summary>
/// Issues a service-principal token: level <see cref="AccessLevel.Service"/> and one permission claim per grant configured
/// for the client. There is no way to obtain a Root token through this grant (docs/DESIGN.md §16).
/// </summary>
public sealed class ClientCredentialsHandler(ClaimNames names, IOptions<TokenServerOptions> options)
    : ICommandHandler<ClientCredentialsCommand, IssuedIdentity>
{
    public Task<Result<IssuedIdentity>> HandleAsync(ClientCredentialsCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);

        var client = options.Value.Clients.FirstOrDefault(candidate => string.Equals(candidate.ClientId, command.ClientId, StringComparison.Ordinal));
        if (client is null)
        {
            return Task.FromResult<Result<IssuedIdentity>>(
                Error.Unauthorized(GrantErrors.InvalidGrant, "This client is not configured for service tokens."));
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

        return Task.FromResult<Result<IssuedIdentity>>(
            new IssuedIdentity(client.ClientId, claims, command.Scopes) { AllowRefresh = false });
    }
}

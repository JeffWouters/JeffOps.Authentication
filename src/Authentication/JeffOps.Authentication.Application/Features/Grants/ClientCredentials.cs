using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Application.Features.Grants.ClientCredentials;

/// <summary>A service authenticating as itself. The protocol layer has already authenticated the client.</summary>
public sealed record ClientCredentialsCommand(string ClientId, IReadOnlyCollection<string> Scopes);

/// <summary>Issues a service-principal token (see <see cref="ServiceIdentity"/>).</summary>
public sealed class ClientCredentialsHandler(ServiceIdentity services) : ICommandHandler<ClientCredentialsCommand, IssuedIdentity>
{
    public Task<Result<IssuedIdentity>> HandleAsync(ClientCredentialsCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        return Task.FromResult(services.For(command.ClientId, command.Scopes));
    }
}

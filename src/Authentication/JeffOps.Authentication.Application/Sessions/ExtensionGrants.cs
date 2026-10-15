using System.Security.Claims;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Application.Sessions;

/// <summary>
/// A token request for an extension grant type (<c>{ExtensionGrantNamespace}:{name}</c>) contributed by a module, such as
/// Delegation (docs/DESIGN.md §12).
/// </summary>
/// <param name="ClientId">The authenticated client making the request.</param>
/// <param name="Scopes">The requested scopes.</param>
/// <param name="Parameters">The request's other parameters.</param>
/// <param name="Actor">
/// The principal of the request's <c>actor_token</c> (RFC 8693 §2.1): an access token this server issued, already validated.
/// Null when the request carried none.
/// </param>
public sealed record ExtensionGrantRequest(
    string ClientId,
    IReadOnlyCollection<string> Scopes,
    IReadOnlyDictionary<string, string?> Parameters,
    ClaimsPrincipal? Actor)
{
    public string? Parameter(string name) => Parameters.GetValueOrDefault(name);
}

/// <summary>Decides an extension grant. Register with <see cref="ExtensionGrantRegistration"/>.</summary>
public interface IExtensionGrantHandler
{
    /// <summary>The grant's name; the grant type is <c>{ExtensionGrantNamespace}:{Name}</c>.</summary>
    string Name { get; }

    Task<Result<IssuedIdentity>> HandleAsync(ExtensionGrantRequest request, CancellationToken cancellationToken);
}

/// <summary>Declares an extension grant so the server accepts and advertises its grant type.</summary>
public sealed record ExtensionGrantRegistration(string Name);

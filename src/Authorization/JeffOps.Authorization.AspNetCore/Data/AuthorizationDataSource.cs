using System.Net.Http.Json;
using JeffOps.Authorization.Contracts;

namespace JeffOps.Authorization.AspNetCore.Data;

/// <summary>
/// Where a resource service reads the role and policy data it caches. The default reads the management service's HTTP API;
/// a host that co-hosts management can register an implementation that reads its store directly (D13).
/// </summary>
public interface IAuthorizationDataSource
{
    Task<IReadOnlyList<UserAssignmentDto>> GetUserAssignmentsAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken);

    Task<IReadOnlyDictionary<Guid, string[]>> GetRolePermissionsAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<AttributePolicyDto>> GetPoliciesAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<ScopeDto>> GetScopesAsync(CancellationToken cancellationToken);
}

/// <summary>Declares a service's permissions to the management service's registry.</summary>
public interface IPermissionRegistry
{
    Task RegisterAsync(RegisterPermissionsRequest request, CancellationToken cancellationToken);
}

/// <summary>
/// Reads the management service's API. The host authenticates this client, typically with the service-token handler of
/// <c>JeffOps.Authentication.Client</c>, through the <see cref="Microsoft.Extensions.DependencyInjection.IHttpClientBuilder"/>
/// that <c>AddJeffOpsPermissionAuthorization</c> exposes.
/// </summary>
public sealed class HttpAuthorizationDataSource(HttpClient http) : IAuthorizationDataSource, IPermissionRegistry
{
    public const string HttpClientName = "JeffOps.Authorization";

    public async Task<IReadOnlyList<UserAssignmentDto>> GetUserAssignmentsAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken) =>
        await http.GetFromJsonAsync<UserAssignmentDto[]>(AuthorizationRoutes.UserAssignmentsOf(userId, tenantId), cancellationToken).ConfigureAwait(false) ?? [];

    public async Task<IReadOnlyDictionary<Guid, string[]>> GetRolePermissionsAsync(CancellationToken cancellationToken) =>
        await http.GetFromJsonAsync<Dictionary<Guid, string[]>>(AuthorizationRoutes.RolePermissions, cancellationToken).ConfigureAwait(false) ?? [];

    public async Task<IReadOnlyList<AttributePolicyDto>> GetPoliciesAsync(CancellationToken cancellationToken) =>
        await http.GetFromJsonAsync<AttributePolicyDto[]>(AuthorizationRoutes.Policies, cancellationToken).ConfigureAwait(false) ?? [];

    public async Task<IReadOnlyList<ScopeDto>> GetScopesAsync(CancellationToken cancellationToken) =>
        await http.GetFromJsonAsync<ScopeDto[]>(AuthorizationRoutes.Scopes, cancellationToken).ConfigureAwait(false) ?? [];

    public async Task RegisterAsync(RegisterPermissionsRequest request, CancellationToken cancellationToken)
    {
        using var response = await http.PostAsJsonAsync(AuthorizationRoutes.RegisterPermissions, request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
    }
}

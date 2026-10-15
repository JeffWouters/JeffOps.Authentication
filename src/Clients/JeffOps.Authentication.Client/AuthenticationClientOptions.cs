using System.ComponentModel.DataAnnotations;

namespace JeffOps.Authentication.Client;

/// <summary>
/// How a resource service validates platform access tokens. Bound from <see cref="SectionName"/>.
/// </summary>
public sealed class AuthenticationClientOptions
{
    public const string SectionName = "JeffOps:Authentication";

    /// <summary>The token server's issuer URL; its discovery document and signing keys are fetched from here.</summary>
    [Required]
    public string? Authority { get; set; }

    /// <summary>
    /// Audiences this service accepts, for example the shared API audience and the service's own client id. A token for
    /// any other audience is rejected. At least one is required.
    /// </summary>
    [MinLength(1)]
    public IList<string> Audiences { get; } = [];

    /// <summary>Whether the discovery document must be fetched over HTTPS. Null: required everywhere except Development.</summary>
    public bool? RequireHttpsMetadata { get; set; }

    /// <summary>Which service tokens may be scoped to a tenant by trusted internal headers.</summary>
    public ServiceTokenTenantScopingOptions ServiceTokenTenantScoping { get; } = new();
}

/// <summary>
/// A service token is tenant-less. When a service calls another on behalf of a user, it propagates the user's tenant in
/// internal headers (see <c>AddAccessContextPropagation</c>). The callee scopes the service token to that tenant only when
/// enabled here. The edge must strip these headers from external requests (docs/DESIGN.md §10). Off by default.
/// </summary>
public sealed class ServiceTokenTenantScopingOptions
{
    /// <summary>Scope Root-level service tokens by the headers.</summary>
    public bool TrustForRootTokens { get; set; }

    /// <summary>Scope Service-level (per-service) tokens by the headers.</summary>
    public bool TrustForServiceTokens { get; set; }

    public string TenantHeader { get; set; } = "X-Tenant-Id";

    public string ActingTenantHeader { get; set; } = "X-Acting-Tenant-Id";
}

using System.ComponentModel.DataAnnotations;

namespace JeffOps.Authentication.Client;

/// <summary>
/// How a resource service validates platform access tokens. Bound from <see cref="SectionName"/>.
/// </summary>
public sealed class AuthenticationClientOptions
{
    /// <summary>The configuration section the options bind from: <c>JeffOps:Authentication</c>.</summary>
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

    /// <summary>
    /// DPoP (RFC 9449). <see cref="Access.DpopMode.Allowed"/> (default) accepts bearer tokens and checks the proof of every
    /// DPoP-bound token; <see cref="Access.DpopMode.Required"/> accepts only DPoP-bound tokens. Behind a proxy, forward the
    /// original scheme and host, or proofs (bound to the URL the client called) won't match.
    /// </summary>
    public Access.DpopMode Dpop { get; set; } = Access.DpopMode.Allowed;

    /// <summary>
    /// Whether DPoP proofs must carry a nonce this service issued (RFC 9449 §9), so a proof can't be made in advance. Every
    /// answer to a DPoP request carries a fresh nonce in the <c>DPoP-Nonce</c> header; a proof without a valid one is
    /// answered 401 with <c>WWW-Authenticate: DPoP error="use_dpop_nonce"</c>, and the client retries with it. Nonces are
    /// Data-Protected timestamps valid for five minutes: share the Data Protection key ring between instances. Default: false.
    /// </summary>
    public bool DpopNonces { get; set; }

    /// <summary>
    /// How many DPoP proofs the in-process replay cache remembers at once (each for about six minutes). When it is full, new
    /// proofs are refused until old ones expire, so size it for the peak DPoP request rate of one instance times 360 seconds;
    /// about 64 bytes per proof. Ignored when the host registers its own <c>IReplayCache</c>. Default: 500,000.
    /// </summary>
    public int DpopReplayCapacity { get; set; } = Abstractions.Replay.MemoryReplayCache.DefaultCapacity;

    /// <summary>
    /// How many DPoP proofs one key (one client's tokens) may present to this instance per minute; more are refused. Each
    /// proof stays in the shared replay cache for minutes, so without a limit one client could fill it and lock every other
    /// DPoP client out. Default: 3,000 (50 a second).
    /// </summary>
    public int DpopProofsPerKeyPerMinute { get; set; } = 3_000;

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
    /// <summary>
    /// Scope Service-level (client credentials) tokens by the headers. Never applies to a person's token, platform
    /// administrators included: they act in another tenant only through the token server's audited tenant switch.
    /// </summary>
    public bool TrustForServiceTokens { get; set; }

    /// <summary>The header carrying the caller's tenant id. Default: <c>X-Tenant-Id</c>.</summary>
    public string TenantHeader { get; set; } = "X-Tenant-Id";

    /// <summary>The header carrying the tenant a delegated caller acts in. Default: <c>X-Acting-Tenant-Id</c>.</summary>
    public string ActingTenantHeader { get; set; } = "X-Acting-Tenant-Id";
}

using System.ComponentModel.DataAnnotations;

namespace JeffOps.Authentication.Bff;

/// <summary>
/// The backend-for-frontend (docs/DESIGN.md §9.1). Bound from <see cref="SectionName"/>. The BFF is a confidential OpenID
/// Connect client of the token server: the browser holds only an HttpOnly session cookie; tokens stay on the server.
/// </summary>
public sealed class BffOptions
{
    /// <summary>The configuration section the options bind from: <c>JeffOps:Bff</c>.</summary>
    public const string SectionName = "JeffOps:Bff";

    /// <summary>The token server's issuer URL.</summary>
    [Required]
    public Uri? Authority { get; set; }

    /// <summary>The BFF's client id at the token server. Required.</summary>
    [Required]
    public string? ClientId { get; set; }

    /// <summary>The BFF's client secret; the BFF is a confidential client. Required.</summary>
    [Required]
    public string? ClientSecret { get; set; }

    /// <summary>Scopes to request. <c>openid</c> and <c>offline_access</c> are always added.</summary>
    public IList<string> Scopes { get; } = ["profile", "email"];

    /// <summary>The absolute session lifetime; refreshing never extends it.</summary>
    public TimeSpan SessionLifetime { get; set; } = TimeSpan.FromHours(8);

    /// <summary>A session unused this long ends.</summary>
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>How long before the access token expires it is refreshed.</summary>
    public TimeSpan RefreshBeforeExpiry { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// While the session store is unreachable, serve the last known copy of a session to read-only requests for this long.
    /// Zero (default) answers 503 instead.
    /// </summary>
    public TimeSpan StoreOutageGrace { get; set; } = TimeSpan.Zero;

    /// <summary>The session cookie's name; a <c>__Host-</c> prefix is added on HTTPS.</summary>
    public string CookieName { get; set; } = "jeffops-session";

    /// <summary>The header every state-changing request with the session cookie must carry (CSRF protection).</summary>
    public string CsrfHeaderName { get; set; } = "X-JeffOps-Csrf";

    /// <summary>
    /// Token-mediating mode ("OAuth 2.0 for Browser-Based Applications", token-mediating backend): <c>GET /bff/token</c>
    /// hands the browser app the session's short-lived access token (refreshed here when needed), for calling APIs directly.
    /// The refresh token never leaves the BFF. Off by default: proxying through the BFF keeps every token out of the browser,
    /// which is safer; turn this on only for APIs the BFF can't proxy. The request must carry the CSRF header.
    /// </summary>
    public bool TokenMediating { get; set; }

    /// <summary>
    /// Access to the token server's own APIs (account, personal access tokens, credentials, delegation, enterprise). The BFF
    /// requests <see cref="AccountScope"/> and keeps a second access token whose only audience is the token server, fetched by
    /// narrowing a refresh, so the token it sends to APIs can't be used there. <c>/bff/account/{path}</c> forwards to the token
    /// server with it, for paths under <see cref="AccountApiPaths"/> and from the user's own session only (never an acting
    /// one). On automatically with derived sessions, which end grants there. The client must be allowed the scope. Off by default.
    /// </summary>
    public bool AccountApi { get; set; }

    /// <summary>The scope that gets an access token for the token server's own APIs. Default: <c>account</c>.</summary>
    public string AccountScope { get; set; } = "account";

    /// <summary>The token server paths <c>/bff/account/{path}</c> may reach. Default: <c>account/</c>, <c>delegation/</c>, <c>enterprise/</c>.</summary>
    public IList<string> AccountApiPaths { get; } = ["account/", "delegation/", "enterprise/"];

    /// <summary>Whether the session holds an account token: <see cref="AccountApi"/>, or derived sessions.</summary>
    internal bool UsesAccountApi => AccountApi || Delegation.Enabled;

    /// <summary>
    /// Request headers never forwarded to backends (besides <c>Cookie</c>): headers backends trust only from other services,
    /// such as the tenant headers of service-token scoping. Default: <c>X-Tenant-Id</c>, <c>X-Acting-Tenant-Id</c>.
    /// </summary>
    public IList<string> StripRequestHeaders { get; } = ["X-Tenant-Id", "X-Acting-Tenant-Id"];

    /// <summary>The claims of the access token returned by <c>/bff/me</c>.</summary>
    public IList<string> UserClaims { get; } = ["sub", "email", "name", "tid", "org", "lvl", "amr", "step_up", "act_tid", "dlg_scope", "act_kind", "grant_id"];

    /// <summary>Derived sessions for impersonation and tenant switch (docs/DESIGN.md §12). Off by default.</summary>
    public DelegatedSessionOptions Delegation { get; } = new();
}

/// <summary>
/// Derived ("acting") sessions: the browser keeps its own session and gets a second cookie for a session that acts as another
/// user (impersonation) or in another tenant (tenant switch). A derived session is bound to the own session that started it
/// and is only used next to it; its tokens are minted again from the own session's access token before they expire, so
/// revoking the grant or the relationship ends it within one token lifetime.
/// </summary>
public sealed class DelegatedSessionOptions
{
    /// <summary>Whether <c>/bff/acting</c>, <c>/bff/impersonation/*</c> and <c>/bff/tenants/*</c> are mapped.</summary>
    public bool Enabled { get; set; }

    /// <summary>The token server's extension grant namespace. Default: <c>urn:jeffops:grant-type</c>.</summary>
    public string GrantTypeNamespace { get; set; } = "urn:jeffops:grant-type";

    /// <summary>The longest an impersonation session lasts, whatever the grant says. Default: 30 minutes.</summary>
    public TimeSpan ImpersonationLifetime { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>The longest a tenant-switch session lasts. Default: 60 minutes.</summary>
    public TimeSpan TenantSwitchLifetime { get; set; } = TimeSpan.FromMinutes(60);

    /// <summary>The derived session cookie's name; a <c>__Host-</c> prefix is added on HTTPS.</summary>
    public string CookieName { get; set; } = "jeffops-acting";

    /// <summary>The token server route that ends an impersonation grant; <c>{0}</c> is the grant id.</summary>
    public string EndImpersonationPath { get; set; } = "delegation/impersonation/{0}/end";

    /// <summary>The extension grant type that mints impersonation tokens: <see cref="GrantTypeNamespace"/> plus <c>:impersonation</c>.</summary>
    public string ImpersonationGrantType => GrantTypeNamespace + ":impersonation";

    /// <summary>The extension grant type that mints tenant-switch tokens: <see cref="GrantTypeNamespace"/> plus <c>:tenant-switch</c>.</summary>
    public string TenantSwitchGrantType => GrantTypeNamespace + ":tenant-switch";
}

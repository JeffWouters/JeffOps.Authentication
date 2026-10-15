using System.ComponentModel.DataAnnotations;

namespace JeffOps.Authentication.Bff;

/// <summary>
/// The backend-for-frontend (docs/DESIGN.md §9.1). Bound from <see cref="SectionName"/>. The BFF is a confidential OpenID
/// Connect client of the token server: the browser holds only an HttpOnly session cookie; tokens stay on the server.
/// </summary>
public sealed class BffOptions
{
    public const string SectionName = "JeffOps:Bff";

    /// <summary>The token server's issuer URL.</summary>
    [Required]
    public Uri? Authority { get; set; }

    [Required]
    public string? ClientId { get; set; }

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

    public string ImpersonationGrantType => GrantTypeNamespace + ":impersonation";

    public string TenantSwitchGrantType => GrantTypeNamespace + ":tenant-switch";
}

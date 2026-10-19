namespace JeffOps.Authentication.Abstractions.Claims;

/// <summary>
/// The claim names of the claims contract (docs/DESIGN.md §10). Every reader and writer of platform tokens resolves names
/// through one instance of this class, so a host can rename a claim in one place. The defaults are short, JWT-style names.
/// </summary>
/// <remarks>
/// Register a customised instance with <c>services.AddSingleton(new ClaimNames { Tenant = "tenant_id" })</c> before calling
/// any <c>AddJeffOps*</c> method; otherwise <see cref="Default"/> is used.
/// </remarks>
public sealed record ClaimNames
{
    /// <summary>The default claim names.</summary>
    public static ClaimNames Default { get; } = new();

    /// <summary>Subject: a user id (GUID) for users, a client id for services.</summary>
    public string Subject { get; init; } = "sub";

    /// <summary>The caller's home tenant.</summary>
    public string Tenant { get; init; } = "tid";

    /// <summary>The organization that owns the home tenant.</summary>
    public string Organization { get; init; } = "org";

    /// <summary>The active workspace, when the session is workspace-scoped.</summary>
    public string Workspace { get; init; } = "wid";

    /// <summary>The access level; values are the names of <see cref="Access.AccessLevel"/>.</summary>
    public string Level { get; init; } = "lvl";

    /// <summary>The tenant being acted on in a delegated (tenant-switch) session.</summary>
    public string ActingTenant { get; init; } = "act_tid";

    /// <summary>A permission granted to a service principal, once per grant (client-credentials tokens only).</summary>
    public string ServicePermission { get; init; } = "perm";

    /// <summary>A personal access token's permission ceiling, once per entry.</summary>
    public string PatCeiling { get; init; } = "pat_perm";

    /// <summary>A delegated session's scope ceiling, once per scope.</summary>
    public string DelegationScope { get; init; } = "dlg_scope";

    /// <summary>Set to <see cref="StepUpSatisfied"/> when the sign-in satisfied the strong-authentication policy.</summary>
    public string StepUp { get; init; } = "step_up";

    /// <summary>The value of <see cref="StepUp"/> that satisfies step-up.</summary>
    public string StepUpSatisfied { get; init; } = "mfa";

    /// <summary>Authentication methods (RFC 8176).</summary>
    public string AuthenticationMethods { get; init; } = "amr";

    /// <summary>Time of the original interactive sign-in, the basis of the absolute session lifetime.</summary>
    public string AuthenticationTime { get; init; } = "auth_time";

    /// <summary>The kind of credential the token was minted from (for example <c>pat</c>).</summary>
    public string CredentialType { get; init; } = "cred";

    /// <summary>The email address of a user.</summary>
    public string Email { get; init; } = "email";

    /// <summary>The display name of a user.</summary>
    public string Name { get; init; } = "name";

    /// <summary>The actor of an impersonation token (RFC 8693 §4.1): a JSON object whose <c>sub</c> is the acting user.</summary>
    public string Actor { get; init; } = "act";

    /// <summary>Who the actor of an impersonation token is: <c>Platform</c> staff or a <c>Partner</c>.</summary>
    public string ActorKind { get; init; } = "act_kind";

    /// <summary>The delegation grant an impersonation token was minted against.</summary>
    public string DelegationGrant { get; init; } = "grant_id";

    /// <summary>
    /// The sign-in session a token belongs to (OpenID Connect <c>sid</c>): signing out at the token server ends it, and
    /// back-channel logout tokens name it.
    /// </summary>
    public string SessionId { get; init; } = "sid";

    /// <summary>
    /// Further claims that mark an impersonation token. <see cref="Actor"/>, <see cref="ActorKind"/> and
    /// <see cref="DelegationGrant"/> always do, under whatever names they are configured with; any one present marks the token.
    /// </summary>
    public IReadOnlyList<string> ImpersonationMarkers { get; init; } = [];

    /// <summary>Whether <paramref name="claimType"/> marks an impersonation token.</summary>
    public bool IsImpersonationMarker(string claimType) =>
        claimType == Actor || claimType == ActorKind || claimType == DelegationGrant || ImpersonationMarkers.Contains(claimType, StringComparer.Ordinal);
}

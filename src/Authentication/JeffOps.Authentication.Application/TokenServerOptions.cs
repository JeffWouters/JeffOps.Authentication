namespace JeffOps.Authentication.Application;

/// <summary>
/// Options of the token server. Bound from <see cref="SectionName"/>.
/// </summary>
public sealed class TokenServerOptions
{
    public const string SectionName = "JeffOps:TokenServer";

    /// <summary>The issuer URL (absolute). Required outside Development.</summary>
    public Uri? Issuer { get; set; }

    /// <summary>The absolute lifetime of an interactive session, from sign-in; refreshing never extends it.</summary>
    public TimeSpan SessionLifetime { get; set; } = TimeSpan.FromHours(8);

    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>
    /// How long a refresh token that was just redeemed may be redeemed again, so two concurrent refreshes don't sign the user
    /// out. Outside this window, reusing a refresh token revokes the whole token chain. Zero disables the leeway.
    /// </summary>
    public TimeSpan RefreshTokenReuseLeeway { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>The prefix of extension grant types, e.g. <c>urn:jeffops:grant-type:pat</c>.</summary>
    public string ExtensionGrantNamespace { get; set; } = "urn:jeffops:grant-type";

    /// <summary>API scopes and the audiences their tokens are issued for, e.g. <c>api</c> → <c>["api"]</c>.</summary>
    public IDictionary<string, List<string>> ApiScopes { get; } = new Dictionary<string, List<string>>(StringComparer.Ordinal);

    public MfaOptions Mfa { get; } = new();

    public PatOptions Pat { get; } = new();

    /// <summary>
    /// How long a client's back-channel logout endpoint gets to answer before it is given up on (the session ends here
    /// regardless). Clients are told at the same time, so ending a session takes at most this long. Default: 5 seconds.
    /// </summary>
    public TimeSpan BackchannelLogoutTimeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>The OAuth clients the server seeds and keeps in sync at startup.</summary>
    public IList<ClientDefinition> Clients { get; } = [];

    /// <summary>The authentication scheme the authorize endpoint challenges when nobody is signed in (the login UI).</summary>
    public string SignInScheme { get; set; } = "JeffOps.SignIn";

    /// <summary>The permission an operator needs to disable or enable accounts.</summary>
    public string AccountAdministrationPermission { get; set; } = "auth.accounts.manage";

    /// <summary>The permission a service needs to look up accounts (contact details, by email).</summary>
    public string DirectoryLookupPermission { get; set; } = "auth.accounts.lookup";

    public string PatGrantType => $"{ExtensionGrantNamespace}:pat";

    /// <summary>
    /// Whether DPoP proofs at the token endpoint must carry a nonce this server issued (RFC 9449 §8), so a proof can't be made
    /// in advance. A request without a valid one is answered <c>use_dpop_nonce</c> with a fresh nonce in the
    /// <c>DPoP-Nonce</c> header; clients retry with it. Default: false.
    /// </summary>
    public bool RequireDpopNonce { get; set; }

    /// <summary>
    /// The grant type of the extension grant <paramref name="name"/>: <c>{ExtensionGrantNamespace}:{name}</c>, or the name itself
    /// when it is already a URN (standard grants such as RFC 7523's JWT bearer grant).
    /// </summary>
    public string ExtensionGrantType(string name) =>
        name.StartsWith("urn:", StringComparison.Ordinal) ? name : $"{ExtensionGrantNamespace}:{name}";
}

/// <summary>The strong-authentication policy (docs/DESIGN.md §8.1).</summary>
public sealed class MfaOptions
{
    /// <summary>Refuse sign-ins that were not multi-factor. Off by default: whether MFA is available depends on the provider.</summary>
    public bool RequireForSignIn { get; set; }

    /// <summary>Step-up-protected actions need a multi-factor sign-in.</summary>
    public bool RequireForSensitiveActions { get; set; } = true;
}

/// <summary>Personal access tokens (docs/DESIGN.md §7.4).</summary>
public sealed class PatOptions
{
    public string Prefix { get; set; } = "pat_";

    public TimeSpan DefaultLifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>No token lives longer, including tokens created before the maximum was lowered.</summary>
    public TimeSpan MaxLifetime { get; set; } = TimeSpan.FromDays(90);

    /// <summary>Lifetime of the access token a PAT is exchanged for.</summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>Whether a PAT may be marked to allow sensitive (step-up) actions at all.</summary>
    public bool AllowSensitiveActionPats { get; set; } = true;

    /// <summary>Whether every PAT counts as stepped up. Off: only PATs created with AllowSensitiveActions do.</summary>
    public bool PatsSatisfyStepUp { get; set; }

    /// <summary>The lifetime for a request: the default, or the requested number of days within 1..max; null when out of range.</summary>
    public TimeSpan? ResolveLifetime(int? requestedDays)
    {
        if (requestedDays is null)
        {
            return DefaultLifetime < MaxLifetime ? DefaultLifetime : MaxLifetime;
        }

        var requested = TimeSpan.FromDays(requestedDays.Value);
        return requestedDays.Value >= 1 && requested <= MaxLifetime ? requested : null;
    }
}

public enum ClientKind
{
    /// <summary>Holds a secret: a BFF, a server-rendered web app, a service.</summary>
    Confidential,

    /// <summary>Holds no secret: a browser SPA, a native app, a CLI. PKCE is mandatory.</summary>
    Public,
}

/// <summary>An OAuth client the server seeds (docs/DESIGN.md §7.7).</summary>
public sealed class ClientDefinition
{
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Required for confidential clients. Outside Development it must be at least 32 characters.</summary>
    public string? ClientSecret { get; set; }

    public string? DisplayName { get; set; }

    public ClientKind Kind { get; set; } = ClientKind.Confidential;

    /// <summary>
    /// Allowed grant types: <c>authorization_code</c>, <c>refresh_token</c>, <c>client_credentials</c>, and extension grants
    /// such as <c>urn:jeffops:grant-type:pat</c>.
    /// </summary>
    public IList<string> GrantTypes { get; } = [];

    public IList<Uri> RedirectUris { get; } = [];

    public IList<Uri> PostLogoutRedirectUris { get; } = [];

    /// <summary>Scopes the client may request, e.g. <c>openid</c>, <c>profile</c>, <c>offline_access</c>, API scopes.</summary>
    public IList<string> Scopes { get; } = [];

    /// <summary>Permissions stamped on this client's client-credentials tokens (service principal grants).</summary>
    public IList<string> ServicePermissions { get; } = [];

    /// <summary>
    /// Where the server posts an OpenID Connect back-channel <c>logout_token</c> when one of the client's users is disabled,
    /// e.g. <c>https://app.example/bff/backchannel-logout</c>.
    /// </summary>
    public Uri? BackchannelLogoutUri { get; set; }

    /// <summary>
    /// The client's public keys (a JWKS document, as JSON) for <c>private_key_jwt</c> client authentication (RFC 7523): the
    /// client signs an assertion instead of sending a secret. A confidential client with keys needs no secret.
    /// </summary>
    public string? JsonWebKeySet { get; set; }

    /// <summary>Whether authorization requests must be pushed first (PAR, RFC 9126). Default: false.</summary>
    public bool RequirePushedAuthorization { get; set; }

    /// <summary>Whether every token request must carry a DPoP proof, so tokens are bound to the client's key (RFC 9449). Default: false.</summary>
    public bool RequireDpop { get; set; }

    /// <summary>
    /// External identities that may act as this client (workload identity federation): a token from a trusted issuer (a CI
    /// system, Kubernetes, a cloud) with this subject and audience is exchanged for this client's token, with no secret.
    /// </summary>
    public IList<FederatedCredential> FederatedCredentials { get; } = [];
}

/// <summary>
/// A workload identity trusted to act as a client: tokens from <see cref="Issuer"/> (validated against its published keys)
/// whose <c>sub</c> is <see cref="Subject"/> and whose <c>aud</c> contains <see cref="Audience"/>.
/// </summary>
public sealed class FederatedCredential
{
    /// <summary>The external issuer, for example <c>https://token.actions.githubusercontent.com</c>.</summary>
    public Uri? Issuer { get; set; }

    /// <summary>The exact subject, for example <c>repo:contoso/app:ref:refs/heads/main</c>.</summary>
    public string? Subject { get; set; }

    /// <summary>The audience the external token must carry. Default: this server's issuer.</summary>
    public string? Audience { get; set; }
}

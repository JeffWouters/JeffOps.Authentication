namespace JeffOps.Authentication.Federation.Saml;

/// <summary>
/// One SAML 2.0 identity provider (ADFS, Okta, Entra, Ping, ...). Bound from
/// <c>JeffOps:TokenServer:Federation:Saml:{name}</c>, or configured in code with <c>AddSamlProvider</c>.
/// </summary>
public sealed class SamlProviderOptions
{
    /// <summary>The configuration section that holds one subsection per provider, keyed by name.</summary>
    public const string SectionName = "JeffOps:TokenServer:Federation:Saml";

    /// <summary>The button label on the login page. Default: the provider's name.</summary>
    public string? DisplayName { get; set; }

    /// <summary>The identity provider's entity id: the issuer its assertions must carry, and half of every linked login.</summary>
    public string? IdpEntityId { get; set; }

    /// <summary>The identity provider's single sign-on URL (HTTP-Redirect binding).</summary>
    public Uri? IdpSingleSignOnUrl { get; set; }

    /// <summary>The identity provider's signing certificates (base64 DER or PEM). Several during a rollover.</summary>
    public IList<string> IdpSigningCertificates { get; } = [];

    /// <summary>This server's entity id towards the provider. Default: <c>{issuer}signin/saml/{name}</c>.</summary>
    public string? ServiceProviderEntityId { get; set; }

    /// <summary>Attributes that may carry the email address, in order. The NameID is used when it is an email and none is present.</summary>
    public IList<string> EmailAttributes { get; } =
    [
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "email",
        "mail",
        "urn:oid:0.9.2342.19200300.100.1.3",
    ];

    /// <summary>Attributes that may carry the display name, in order.</summary>
    public IList<string> NameAttributes { get; } =
    [
        "http://schemas.microsoft.com/identity/claims/displayname",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "displayName",
        "name",
        "urn:oid:2.16.840.1.113730.3.1.241",
    ];

    /// <summary>
    /// Whether the provider's email addresses count as verified. Set it only for a directory whose users can't choose their own
    /// address (a verified email is trusted for linking and provisioning). Default: false.
    /// </summary>
    public bool EmailVerified { get; set; }

    /// <summary>Authentication context class references that count as multi-factor, for example <c>http://schemas.microsoft.com/claims/multipleauthn</c>.</summary>
    public IList<string> MultiFactorAuthnContexts { get; } = [];

    /// <summary>How long a sign-in may take at the provider. Default: 10 minutes.</summary>
    public TimeSpan SignInTimeout { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// The identity provider's single logout URL (HTTP-Redirect binding), where logout responses go. Without it, logout
    /// requests from the provider are still honoured but answered with a plain page.
    /// </summary>
    public Uri? IdpSingleLogoutUrl { get; set; }

    /// <summary>
    /// This server's signing certificate with its private key, for signed AuthnRequests and logout responses (many identity
    /// providers require them). Set in code, or through <see cref="SigningCertificatePfx"/>. Publish its public part to the
    /// provider through the metadata endpoint.
    /// </summary>
    public System.Security.Cryptography.X509Certificates.X509Certificate2? SigningCertificate { get; set; }

    /// <summary>The signing certificate as a base64 PKCS#12 (PFX) blob, for configuration from a secret store.</summary>
    public string? SigningCertificatePfx { get; set; }

    /// <summary>The password of <see cref="SigningCertificatePfx"/>, if any.</summary>
    public string? SigningCertificatePassword { get; set; }
}

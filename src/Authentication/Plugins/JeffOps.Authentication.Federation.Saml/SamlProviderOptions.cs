namespace JeffOps.Authentication.Federation.Saml;

/// <summary>
/// One SAML 2.0 identity provider (ADFS, Okta, Entra, Ping, ...). Bound from
/// <c>JeffOps:TokenServer:Federation:Saml:{name}</c>, or configured in code with <c>AddSamlProvider</c>.
/// </summary>
public sealed class SamlProviderOptions
{
    public const string SectionName = "JeffOps:TokenServer:Federation:Saml";

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

    /// <summary>Whether the provider's email addresses are verified (true for a corporate directory). Default: true.</summary>
    public bool EmailVerified { get; set; } = true;

    /// <summary>Authentication context class references that count as multi-factor, for example <c>http://schemas.microsoft.com/claims/multipleauthn</c>.</summary>
    public IList<string> MultiFactorAuthnContexts { get; } = [];

    /// <summary>How long a sign-in may take at the provider. Default: 10 minutes.</summary>
    public TimeSpan SignInTimeout { get; set; } = TimeSpan.FromMinutes(10);
}

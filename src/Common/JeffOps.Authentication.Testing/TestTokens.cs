using System.Security.Claims;
using System.Security.Cryptography;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace JeffOps.Authentication.Testing;

/// <summary>
/// The caller a test token describes, built fluently: <c>TestPrincipal.User().InTenant(t).SteppedUp()</c>. Claim names follow
/// the claims contract (docs/DESIGN.md §10), so the resource service under test reads it exactly like a real token.
/// </summary>
public sealed record TestPrincipal
{
    /// <summary>The <c>sub</c>: a user id, or a client id for a service.</summary>
    public required string Subject { get; init; }

    /// <summary>The access level (<c>lvl</c>).</summary>
    public AccessLevel Level { get; init; } = AccessLevel.Tenant;

    /// <summary>The home tenant (<c>tid</c>).</summary>
    public Guid? TenantId { get; init; }

    /// <summary>The organization (<c>org</c>).</summary>
    public Guid? OrganizationId { get; init; }

    /// <summary>The workspace (<c>wid</c>).</summary>
    public Guid? WorkspaceId { get; init; }

    /// <summary>The tenant a delegated (tenant-switch) session acts in (<c>act_tid</c>).</summary>
    public Guid? ActingTenantId { get; init; }

    /// <summary>The email address.</summary>
    public string? Email { get; init; }

    /// <summary>The display name.</summary>
    public string? Name { get; init; }

    /// <summary>Whether the sign-in satisfied step-up (<c>step_up=mfa</c>).</summary>
    public bool IsSteppedUp { get; init; }

    /// <summary>Permissions of a service principal (<c>perm</c> claims).</summary>
    public IReadOnlyList<string> ServicePermissions { get; init; } = [];

    /// <summary>A personal access token's ceiling (<c>pat_perm</c> claims).</summary>
    public IReadOnlyList<string> PatCeiling { get; init; } = [];

    /// <summary>Delegation scopes (<c>dlg_scope</c> claims).</summary>
    public IReadOnlyList<string> DelegationScopes { get; init; } = [];

    /// <summary>Marks the token as an impersonation of the subject by this actor.</summary>
    public Guid? ImpersonatedBy { get; init; }

    /// <summary>Any other claims.</summary>
    public IReadOnlyList<(string Type, string Value)> Extra { get; init; } = [];

    /// <summary>A user in their own session.</summary>
    public static TestPrincipal User(Guid? id = null) => new() { Subject = (id ?? Guid.NewGuid()).ToString() };

    /// <summary>A service principal (client credentials) with <paramref name="permissions"/>.</summary>
    public static TestPrincipal Service(string clientId, params string[] permissions) =>
        new() { Subject = clientId, Level = AccessLevel.Service, ServicePermissions = permissions };

    /// <summary>A platform administrator, stepped up.</summary>
    public static TestPrincipal Root(Guid? id = null) => User(id) with { Level = AccessLevel.Root, IsSteppedUp = true };

    /// <summary>The same caller in <paramref name="tenantId"/>.</summary>
    public TestPrincipal InTenant(Guid tenantId, Guid? organizationId = null) => this with { TenantId = tenantId, OrganizationId = organizationId ?? OrganizationId };

    /// <summary>The same caller after a multi-factor sign-in.</summary>
    public TestPrincipal SteppedUp() => this with { IsSteppedUp = true };

    /// <summary>The same caller acting in another tenant (tenant switch) with <paramref name="delegationScopes"/>.</summary>
    public TestPrincipal ActingIn(Guid tenantId, params string[] delegationScopes) =>
        this with { ActingTenantId = tenantId, Level = AccessLevel.Delegated, DelegationScopes = delegationScopes };

    /// <summary>The same subject, impersonated by <paramref name="actor"/>.</summary>
    public TestPrincipal ImpersonatedByActor(Guid actor) => this with { ImpersonatedBy = actor };

    /// <summary>The same caller through a personal access token limited to <paramref name="permissions"/>.</summary>
    public TestPrincipal WithPatCeiling(params string[] permissions) => this with { PatCeiling = permissions };

    /// <summary>The same caller with one more claim.</summary>
    public TestPrincipal With(string type, string value) => this with { Extra = [.. Extra, (type, value)] };

    /// <summary>The claims of the token, named by <paramref name="names"/>.</summary>
    public IReadOnlyList<Claim> Claims(ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(names);
        var claims = new List<Claim> { new(names.Subject, Subject), new(names.Level, Level.ToString()) };

        void Add(string type, object? value)
        {
            if (value is not null)
            {
                claims.Add(new Claim(type, value.ToString()!));
            }
        }

        Add(names.Tenant, TenantId);
        Add(names.Organization, OrganizationId);
        Add(names.Workspace, WorkspaceId);
        Add(names.ActingTenant, ActingTenantId);
        Add(names.Email, Email);
        Add(names.Name, Name);
        if (IsSteppedUp)
        {
            claims.Add(new Claim(names.StepUp, names.StepUpSatisfied));
        }

        claims.AddRange(ServicePermissions.Select(permission => new Claim(names.ServicePermission, permission)));
        claims.AddRange(PatCeiling.Select(permission => new Claim(names.PatCeiling, permission)));
        claims.AddRange(DelegationScopes.Select(scope => new Claim(names.DelegationScope, scope)));
        if (ImpersonatedBy is not null)
        {
            claims.Add(new Claim(names.ActorKind, "Platform"));
            claims.Add(new Claim(names.DelegationGrant, Guid.NewGuid().ToString()));
        }

        claims.AddRange(Extra.Select(extra => new Claim(extra.Type, extra.Value)));
        return claims;
    }
}

/// <summary>
/// Issues signed access tokens for tests and makes a resource service (set up with <c>AddJeffOpsAuthenticationClient</c>) trust
/// them, with no token server running. Each issuer has its own key, so tokens of another issuer are rejected.
/// </summary>
public sealed class TestTokenIssuer : IDisposable
{
    /// <summary>The issuer of test tokens.</summary>
    public const string Issuer = "https://test-issuer.jeffops.local/";

    private readonly RSA _key = RSA.Create(2048);
    private readonly RsaSecurityKey _securityKey;
    private readonly TimeProvider _time;

    /// <summary>
    /// An issuer of tokens for <paramref name="audience"/>, with claim names <paramref name="names"/> (default: the contract's),
    /// timing tokens by <paramref name="time"/> (default: the system clock; pass the host's fake clock to test expiry).
    /// </summary>
    public TestTokenIssuer(string audience = "api", ClaimNames? names = null, TimeProvider? time = null)
    {
        _time = time ?? TimeProvider.System;
        Audience = audience;
        Names = names ?? ClaimNames.Default;
        _securityKey = new RsaSecurityKey(_key) { KeyId = "jeffops-test-" + Guid.NewGuid().ToString("N")[..8] };
    }

    /// <summary>The default audience of issued tokens.</summary>
    public string Audience { get; }

    /// <summary>The claim names used.</summary>
    public ClaimNames Names { get; }

    /// <summary>A token for <paramref name="principal"/>, valid for <paramref name="lifetime"/> (default five minutes).</summary>
    public string Token(TestPrincipal principal, TimeSpan? lifetime = null, string? audience = null)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var now = _time.GetUtcNow().UtcDateTime;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            TokenType = "at+jwt",
            Issuer = Issuer,
            Audience = audience ?? Audience,
            Subject = new ClaimsIdentity(principal.Claims(Names)),
            IssuedAt = now,
            NotBefore = now.AddSeconds(-5),
            Expires = now + (lifetime ?? TimeSpan.FromMinutes(5)),
            SigningCredentials = new SigningCredentials(_securityKey, SecurityAlgorithms.RsaSha256),
        });
    }

    /// <summary>Makes the JWT bearer scheme trust this issuer instead of fetching metadata from an authority.</summary>
    public void Trust(JwtBearerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var configuration = new OpenIdConnectConfiguration { Issuer = Issuer };
        configuration.SigningKeys.Add(_securityKey);
        options.Authority = Issuer;
        options.Configuration = configuration;
        options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(configuration);
        options.TokenValidationParameters.ValidIssuer = Issuer;
    }

    /// <inheritdoc />
    public void Dispose() => _key.Dispose();
}

/// <summary>Wiring for test hosts.</summary>
public static class TestTokenServiceCollectionExtensions
{
    /// <summary>
    /// Makes the default JWT bearer scheme trust <paramref name="issuer"/>. Call it after <c>AddJeffOpsAuthenticationClient</c>,
    /// with <c>JeffOps:Authentication:Authority</c> set to <see cref="TestTokenIssuer.Issuer"/> and the issuer's audience accepted.
    /// </summary>
    public static IServiceCollection AddJeffOpsTestTokens(this IServiceCollection services, TestTokenIssuer issuer)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(issuer);
        services.PostConfigure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, issuer.Trust);
        return services;
    }
}

/// <summary>A settable <see cref="ICurrentUser"/> for unit tests of code that depends on it.</summary>
public sealed class FakeCurrentUser(Guid? userId = null, string? email = null, string? displayName = null) : ICurrentUser
{
    /// <inheritdoc />
    public bool IsAuthenticated => UserId is not null;

    /// <inheritdoc />
    public Guid? UserId { get; set; } = userId;

    /// <inheritdoc />
    public string? Email { get; set; } = email;

    /// <inheritdoc />
    public string? DisplayName { get; set; } = displayName;
}

/// <summary>A settable <see cref="IAccessContextAccessor"/> for unit tests.</summary>
public sealed class FakeAccessContextAccessor(AccessContext context) : IAccessContextAccessor
{
    /// <summary>The context returned.</summary>
    public AccessContext Context { get; set; } = context;

    /// <inheritdoc />
    public AccessContext GetAccessContext() => Context;
}

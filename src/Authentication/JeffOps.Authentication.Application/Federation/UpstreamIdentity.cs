using System.Security.Claims;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Domain.Accounts;

namespace JeffOps.Authentication.Application.Federation;

/// <summary>
/// The identity a user signed in with at an external provider, for first-party clients that need it
/// (<see cref="ClientDefinition.ForwardUpstreamIdentity"/>, <see cref="ClientDefinition.UpstreamClaims"/>): the provider
/// (<c>idp</c>), its issuer and the user's subject there (<c>idp_iss</c>, <c>idp_sub</c>; for Entra the directory's issuer
/// and the user's <c>oid</c>), and chosen claims of the provider's answer (for example <c>groups</c>, <c>wids</c>). They go
/// into access tokens only, and only for sign-ins through a provider configured on this server: never a provider a tenant
/// registered (its issuer and claims are the tenant's to choose), never a local account. <c>idp</c> comes along with
/// anything forwarded, so a refresh knows where the claims came from.
/// </summary>
public static class UpstreamIdentity
{
    /// <summary>The claim naming the provider the user signed in with.</summary>
    public const string ProviderClaim = "idp";

    /// <summary>The claim with the provider's issuer, as this server links logins (lowercase, no trailing slash).</summary>
    public const string IssuerClaim = "idp_iss";

    /// <summary>The claim with the user's subject at the provider, as this server links logins (lowercase).</summary>
    public const string SubjectClaim = "idp_sub";

    /// <summary>In the sign-in cookie the upstream claims carry this prefix, so nothing mistakes them for the session's own.</summary>
    private const string SignInPrefix = "jeffops:upstream:";

    /// <summary>Claim types a client can't receive from upstream: they belong to this server's tokens.</summary>
    private static readonly HashSet<string> Protocol = new(StringComparer.Ordinal)
    {
        "iss", "aud", "exp", "nbf", "iat", "jti", "azp", "client_id", "scope", "cnf", "oi_au_id", "oi_tkn_id", "acr",
        ProviderClaim, IssuerClaim, SubjectClaim,
    };

    /// <summary>Whether <paramref name="claimType"/> is this server's own (it can't be taken from a provider).</summary>
    public static bool IsReserved(string claimType, ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(names);
        return string.IsNullOrWhiteSpace(claimType)
            || claimType.StartsWith("jeffops:", StringComparison.Ordinal)
            || Protocol.Contains(claimType)
            || claimType == names.Subject || claimType == names.Tenant || claimType == names.Organization || claimType == names.Workspace
            || claimType == names.Level || claimType == names.ActingTenant || claimType == names.ServicePermission || claimType == names.PatCeiling
            || claimType == names.DelegationScope || claimType == names.StepUp || claimType == names.AuthenticationMethods
            || claimType == names.AuthenticationTime || claimType == names.CredentialType || claimType == names.Email || claimType == names.Name
            || claimType == names.SessionId || names.IsImpersonationMarker(claimType);
    }

    /// <summary>
    /// What the sign-in cookie keeps of an external sign-in: the provider's issuer and the user's subject there, and the
    /// provider's claims of <paramref name="claimTypes"/>. Nothing for a provider a tenant registered.
    /// </summary>
    public static IEnumerable<Claim> Capture(string provider, ExternalLoginKey login, ClaimsPrincipal providerClaims, IEnumerable<string> claimTypes)
    {
        ArgumentNullException.ThrowIfNull(login);
        ArgumentNullException.ThrowIfNull(providerClaims);
        ArgumentNullException.ThrowIfNull(claimTypes);
        if (string.IsNullOrEmpty(provider) || TenantProviderNames.IsTenantProvider(provider))
        {
            yield break;
        }

        yield return new Claim(SignInPrefix + IssuerClaim, login.Issuer);
        yield return new Claim(SignInPrefix + SubjectClaim, login.Subject);
        foreach (var type in claimTypes.Distinct(StringComparer.Ordinal))
        {
            foreach (var claim in providerClaims.FindAll(type))
            {
                yield return new Claim(SignInPrefix + type, claim.Value, claim.ValueType);
            }
        }
    }

    /// <summary>The upstream claims <paramref name="client"/> gets from a sign-in (the sign-in cookie's principal).</summary>
    public static IReadOnlyList<Claim> FromSignIn(ClaimsPrincipal? signIn, ClientDefinition? client, ClaimNames names)
    {
        var provider = SignInPrincipal.ProviderOf(signIn);
        if (signIn is null || client is null || !Forwards(provider))
        {
            return [];
        }

        var claims = new List<Claim>();
        if (client.ForwardUpstreamIdentity
            && signIn.FindFirst(SignInPrefix + IssuerClaim)?.Value is { Length: > 0 } issuer
            && signIn.FindFirst(SignInPrefix + SubjectClaim)?.Value is { Length: > 0 } subject)
        {
            claims.Add(new Claim(IssuerClaim, issuer));
            claims.Add(new Claim(SubjectClaim, subject));
        }

        foreach (var type in Allowed(client, names))
        {
            claims.AddRange(signIn.FindAll(SignInPrefix + type).Select(claim => new Claim(type, claim.Value, claim.ValueType)));
        }

        if (claims.Count > 0)
        {
            claims.Insert(0, new Claim(ProviderClaim, provider!));
        }

        return claims;
    }

    /// <summary>
    /// The upstream claims <paramref name="client"/> keeps on a refresh: those the stored grant carries, within what the client
    /// may receive now (its settings may have changed since the sign-in).
    /// </summary>
    public static IReadOnlyList<Claim> FromGrant(ClaimsPrincipal stored, ClientDefinition? client, ClaimNames names)
    {
        ArgumentNullException.ThrowIfNull(stored);
        if (client is null || !Forwards(stored.FindFirst(ProviderClaim)?.Value))
        {
            return [];
        }

        var claims = new List<Claim>();
        if (client.ForwardUpstreamIdentity)
        {
            claims.AddRange(stored.FindAll(claim => claim.Type is IssuerClaim or SubjectClaim).Select(claim => new Claim(claim.Type, claim.Value)));
        }

        foreach (var type in Allowed(client, names))
        {
            claims.AddRange(stored.FindAll(type).Select(claim => new Claim(type, claim.Value, claim.ValueType)));
        }

        if (claims.Count > 0)
        {
            claims.Insert(0, new Claim(ProviderClaim, stored.FindFirst(ProviderClaim)!.Value));
        }

        return claims;
    }

    private static bool Forwards(string? provider) =>
        !string.IsNullOrEmpty(provider) && provider != ClientProviders.Local && !TenantProviderNames.IsTenantProvider(provider);

    private static IEnumerable<string> Allowed(ClientDefinition client, ClaimNames names) =>
        client.UpstreamClaims.Where(type => !IsReserved(type, names)).Distinct(StringComparer.Ordinal);
}

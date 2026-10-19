using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Application.Features.Grants.WorkloadIdentity;

/// <summary>An external token, validated against its issuer's published keys.</summary>
public sealed record ExternalToken(Uri Issuer, string Subject, IReadOnlyList<string> Audiences)
{
    /// <summary>When the token was issued (<c>iat</c>), if it says.</summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>When the token expires (<c>exp</c>).</summary>
    public DateTimeOffset ExpiresAt { get; init; }
}

/// <summary>
/// Validates a token from an external issuer (a CI system, Kubernetes, a cloud) by its OpenID Connect discovery document and
/// keys. Throws <see cref="HttpRequestException"/> when the issuer can't be reached.
/// </summary>
public interface IExternalTokenValidator
{
    /// <returns>The token, or null when it is invalid, expired or not from <paramref name="issuer"/> for <paramref name="audience"/>.</returns>
    Task<ExternalToken?> ValidateAsync(string token, Uri issuer, string audience, CancellationToken cancellationToken);
}

/// <summary>
/// Workload identity federation (RFC 7523 JWT bearer grant): a workload presents a token its platform issued, and gets the
/// configured client's service token — no client secret to store or rotate. The token must come from an issuer listed in the
/// client's <see cref="ClientDefinition.FederatedCredentials"/>, for exactly that subject and audience.
/// </summary>
public sealed class WorkloadIdentityGrantHandler(
    IExternalTokenValidator validator,
    ServiceIdentity services,
    IAuditSink audit,
    IOptions<TokenServerOptions> options,
    TimeProvider time) : IExtensionGrantHandler
{
    public const string GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    public string Name => GrantType;

    public async Task<Result<IssuedIdentity>> HandleAsync(ExtensionGrantRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var settings = options.Value;

        var client = settings.Clients.FirstOrDefault(candidate => string.Equals(candidate.ClientId, request.ClientId, StringComparison.Ordinal));
        if (client is not { FederatedCredentials.Count: > 0 } || request.Parameter("assertion") is not { Length: > 0 } assertion)
        {
            return Error.Unauthorized(GrantErrors.InvalidGrant, "This client accepts no external identities, or the assertion is missing.");
        }

        foreach (var credential in client.FederatedCredentials.Where(credential => credential.Issuer is not null && !string.IsNullOrWhiteSpace(credential.Subject)))
        {
            var audience = credential.Audience ?? settings.Issuer?.AbsoluteUri ?? request.ClientId;
            ExternalToken? token;
            try
            {
                token = await validator.ValidateAsync(assertion, credential.Issuer!, audience, cancellationToken).ConfigureAwait(false);
            }
            catch (HttpRequestException)
            {
                return Error.Unavailable(GrantErrors.DirectoryUnavailable, "The workload's identity provider could not be reached. Try again.");
            }

            if (token is null || !string.Equals(token.Subject, credential.Subject, StringComparison.Ordinal))
            {
                continue;
            }

            // Platform tokens are presented again until they expire (a workload re-exchanges its token), so they aren't
            // one-time; how long one can be used is capped instead.
            if (token.ExpiresAt - (token.IssuedAt ?? time.GetUtcNow()) > credential.MaxTokenLifetime)
            {
                return Error.Unauthorized(GrantErrors.TokenInvalid, "The assertion is valid for longer than this client accepts.");
            }

            await audit.WriteAsync(new AuditRecord("workload.signed_in", "client", client.ClientId)
            {
                OccurredAt = time.GetUtcNow(),
                Details = new Dictionary<string, string?> { ["issuer"] = token.Issuer.AbsoluteUri, ["subject"] = token.Subject },
            }, cancellationToken).ConfigureAwait(false);
            return services.For(client.ClientId, request.Scopes);
        }

        return Error.Unauthorized(GrantErrors.TokenInvalid, "The assertion doesn't match any trusted workload identity of this client.");
    }
}

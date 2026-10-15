namespace JeffOps.Authentication.Abstractions.Contracts;

/// <summary>Creates a personal access token for the caller.</summary>
/// <param name="Name">A label for the token.</param>
/// <param name="ExpiresInDays">Lifetime in days; the server's default when null, never more than its maximum.</param>
/// <param name="Permissions">An optional permission ceiling; tokens minted from the PAT can do at most this.</param>
/// <param name="AllowSensitiveActions">Whether the PAT may perform step-up-protected actions.</param>
public sealed record CreatePersonalAccessTokenRequest(string Name, int? ExpiresInDays = null, IReadOnlyList<string>? Permissions = null, bool AllowSensitiveActions = false);

/// <summary>The created token. <see cref="Secret"/> is shown once and never stored.</summary>
public sealed record CreatePersonalAccessTokenResponse(Guid Id, string Name, string Secret, DateTimeOffset ExpiresAt);

/// <summary>A personal access token as listed to its owner (never the secret).</summary>
public sealed record PersonalAccessTokenDto(
    Guid Id,
    string Name,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? LastUsedAt,
    bool Revoked,
    bool Active,
    IReadOnlyList<string> Permissions,
    bool AllowSensitiveActions);

/// <summary>An account's contact details, returned to services by the directory lookup.</summary>
public sealed record AccountContactDto(Guid Id, string Email, string DisplayName, bool EmailVerified);

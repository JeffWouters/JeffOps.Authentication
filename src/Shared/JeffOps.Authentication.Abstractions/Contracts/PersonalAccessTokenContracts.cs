namespace JeffOps.Authentication.Abstractions.Contracts;

/// <summary>Creates a personal access token for the caller.</summary>
/// <param name="Name">A label for the token.</param>
/// <param name="ExpiresInDays">Lifetime in days; the server's default when null, never more than its maximum.</param>
/// <param name="Permissions">An optional permission ceiling; tokens minted from the PAT can do at most this.</param>
/// <param name="AllowSensitiveActions">Whether the PAT may perform step-up-protected actions.</param>
public sealed record CreatePersonalAccessTokenRequest(string Name, int? ExpiresInDays = null, IReadOnlyList<string>? Permissions = null, bool AllowSensitiveActions = false);

/// <summary>The created token. <see cref="Secret"/> is shown once and never stored.</summary>
/// <param name="Id">The token's id, used to list or revoke it.</param>
/// <param name="Name">The token's label.</param>
/// <param name="Secret">The token itself, which the holder exchanges for access tokens; returned only in this response.</param>
/// <param name="ExpiresAt">When the token stops working.</param>
public sealed record CreatePersonalAccessTokenResponse(Guid Id, string Name, string Secret, DateTimeOffset ExpiresAt);

/// <summary>A personal access token as listed to its owner (never the secret).</summary>
/// <param name="Id">The token's id.</param>
/// <param name="Name">The token's label.</param>
/// <param name="CreatedAt">When the token was created.</param>
/// <param name="ExpiresAt">When the token expires.</param>
/// <param name="LastUsedAt">When the token was last used; null if never.</param>
/// <param name="Revoked">Whether the token has been revoked.</param>
/// <param name="Active">Whether the token can still be used: neither revoked nor expired.</param>
/// <param name="Permissions">The token's permission ceiling; empty when it has none.</param>
/// <param name="AllowSensitiveActions">Whether the token may perform step-up-protected actions.</param>
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
/// <param name="Id">The account id.</param>
/// <param name="Email">The account's email address.</param>
/// <param name="DisplayName">The account's display name.</param>
/// <param name="EmailVerified">Whether the email address has been verified.</param>
public sealed record AccountContactDto(Guid Id, string Email, string DisplayName, bool EmailVerified);

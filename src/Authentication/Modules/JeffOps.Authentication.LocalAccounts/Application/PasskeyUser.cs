namespace JeffOps.Authentication.LocalAccounts.Application;

/// <summary>
/// The user as the WebAuthn ceremony sees it: the account id (the WebAuthn user handle), email and display name. Plain data,
/// so the ceremony library stays an infrastructure detail.
/// </summary>
public sealed class PasskeyUser
{
    public required string Id { get; init; }

    public required string Email { get; init; }

    public string? DisplayName { get; init; }
}

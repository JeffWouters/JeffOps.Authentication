namespace JeffOps.Authentication.Abstractions.Access;

/// <summary>
/// The authenticated caller of the current request, read from validated token claims.
/// </summary>
public interface ICurrentUser
{
    /// <summary>Whether the request carries a validated token; false for anonymous callers.</summary>
    bool IsAuthenticated { get; }

    /// <summary>The user id; null for anonymous callers and for service principals (whose subject is not a GUID).</summary>
    Guid? UserId { get; }

    /// <summary>The user's email address from the token; null when the token carries none, as for a service principal.</summary>
    string? Email { get; }

    /// <summary>The user's display name from the token; null when the token carries none.</summary>
    string? DisplayName { get; }
}

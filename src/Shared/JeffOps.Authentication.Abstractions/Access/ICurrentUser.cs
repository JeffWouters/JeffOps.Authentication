namespace JeffOps.Authentication.Abstractions.Access;

/// <summary>
/// The authenticated caller of the current request, read from validated token claims.
/// </summary>
public interface ICurrentUser
{
    bool IsAuthenticated { get; }

    /// <summary>The user id; null for anonymous callers and for service principals (whose subject is not a GUID).</summary>
    Guid? UserId { get; }

    string? Email { get; }

    string? DisplayName { get; }
}

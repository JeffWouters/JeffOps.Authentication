using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.LocalAccounts.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.LocalAccounts.Application.Features.Passkeys;

/// <summary>A verified passkey, as the WebAuthn ceremony (ASP.NET Core Identity) reported it.</summary>
public sealed record PasskeyData(
    byte[] CredentialId,
    byte[] PublicKey,
    string? Name,
    DateTimeOffset CreatedAt,
    uint SignCount,
    string[]? Transports,
    bool IsUserVerified,
    bool IsBackupEligible,
    bool IsBackedUp,
    byte[] AttestationObject,
    byte[] ClientDataJson);

public sealed record PasskeyDto(string Id, string? Name, DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt, bool IsBackedUp);

/// <summary>Stores a passkey the caller just registered. Accounts without local credentials (federated users) get them now.</summary>
public sealed record AddPasskeyCommand(Guid AccountId, PasskeyData Passkey);

public sealed class AddPasskeyHandler(ILocalCredentialRepository credentials, IAccountRepository accounts, ILocalUnitOfWork unitOfWork, TimeProvider time)
    : ICommandHandler<AddPasskeyCommand, PasskeyDto>
{
    public async Task<Result<PasskeyDto>> HandleAsync(AddPasskeyCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var now = time.GetUtcNow();
        var data = command.Passkey;

        if (await accounts.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false) is not { CanAuthenticate: true })
        {
            return Error.Forbidden(LocalAccountErrors.AccountInactive, "The account is not active.");
        }

        if (await credentials.FindByPasskeyAsync(data.CredentialId, cancellationToken).ConfigureAwait(false) is { } owner && owner.Id != command.AccountId)
        {
            return Error.Conflict(LocalAccountErrors.AlreadyEnabled, "This passkey belongs to another account.");
        }

        var credential = await credentials.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (credential is null)
        {
            credential = LocalCredential.Create(command.AccountId, now);
            credentials.Add(credential);
        }

        credential.SavePasskey(data.CredentialId, data.PublicKey, data.Name, data.CreatedAt, data.SignCount, data.Transports,
            data.IsUserVerified, data.IsBackupEligible, data.IsBackedUp, data.AttestationObject, data.ClientDataJson, now);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return PasskeyMapping.ToDto(credential.FindPasskey(data.CredentialId)!);
    }
}

/// <summary>
/// Completes a passkey sign-in the ceremony verified: records the new signature counter and answers the sign-in methods.
/// A user-verified passkey is multi-factor on its own (possession plus biometrics or PIN).
/// </summary>
public sealed record PasskeySignInCommand(Guid AccountId, PasskeyData Passkey);

public sealed class PasskeySignInHandler(
    ILocalCredentialRepository credentials,
    IAccountRepository accounts,
    IHomeRealmDirectory realms,
    IPendingLinks pendingLinks,
    ILocalUnitOfWork unitOfWork,
    TimeProvider time)
    : ICommandHandler<PasskeySignInCommand, LocalSignInResult>
{
    public async Task<Result<LocalSignInResult>> HandleAsync(PasskeySignInCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var data = command.Passkey;

        var credential = await credentials.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (credential?.FindPasskey(data.CredentialId) is null)
        {
            return LocalSignInResult.Failed;
        }

        credential.SavePasskey(data.CredentialId, data.PublicKey, data.Name, data.CreatedAt, data.SignCount, data.Transports,
            data.IsUserVerified, data.IsBackupEligible, data.IsBackedUp, data.AttestationObject, data.ClientDataJson, time.GetUtcNow());
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);

        if (await accounts.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false) is not { CanAuthenticate: true } account)
        {
            return new LocalSignInResult(LocalSignInStatus.AccountInactive);
        }

        if (HomeRealm.DomainOf(account.Email) is { } domain
            && await realms.FindByDomainAsync(domain, cancellationToken).ConfigureAwait(false) is { SsoOnly: true } realm
            && !pendingLinks.Confirms(account.Id, realm))
        {
            return new LocalSignInResult(LocalSignInStatus.SsoRequired);
        }

        List<string> methods = [data.IsBackupEligible ? "swk" : "hwk"];
        if (data.IsUserVerified)
        {
            methods.AddRange(["user", "mfa"]);
        }

        return new LocalSignInResult(LocalSignInStatus.SignedIn, command.AccountId, methods);
    }
}

public sealed record ListPasskeysQuery(Guid AccountId);

public sealed class ListPasskeysHandler(ILocalCredentialRepository credentials) : IQueryHandler<ListPasskeysQuery, IReadOnlyList<PasskeyDto>>
{
    public async Task<Result<IReadOnlyList<PasskeyDto>>> HandleAsync(ListPasskeysQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var credential = await credentials.FindAsync(query.AccountId, cancellationToken).ConfigureAwait(false);
        return Result.Success<IReadOnlyList<PasskeyDto>>([.. (credential?.Passkeys ?? []).Select(PasskeyMapping.ToDto)]);
    }
}

public sealed record RemovePasskeyCommand(Guid AccountId, string PasskeyId);

public sealed class RemovePasskeyHandler(ILocalCredentialRepository credentials, ILocalUnitOfWork unitOfWork, CredentialChangeSessions sessions)
    : ICommandHandler<RemovePasskeyCommand>
{
    public async Task<Result> HandleAsync(RemovePasskeyCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var credential = await credentials.FindAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (credential is null || !PasskeyMapping.TryDecode(command.PasskeyId, out var id) || !credential.RemovePasskey(id))
        {
            return Error.NotFound(LocalAccountErrors.NotFound, "No such passkey.");
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await sessions.RevokeAsync(command.AccountId, "passkey_removed", cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

internal static class PasskeyMapping
{
    public static PasskeyDto ToDto(StoredPasskey passkey) =>
        new(Encode(passkey.CredentialId), passkey.Name, passkey.CreatedAt, passkey.LastUsedAt, passkey.IsBackedUp);

    public static string Encode(byte[] id) => Convert.ToBase64String(id).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static bool TryDecode(string value, out byte[] id)
    {
        var base64 = (value ?? string.Empty).Replace('-', '+').Replace('_', '/');
        base64 = base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '=');
        id = new byte[base64.Length];
        if (Convert.TryFromBase64String(base64, id, out var written) && written > 0)
        {
            id = id[..written];
            return true;
        }

        return false;
    }
}

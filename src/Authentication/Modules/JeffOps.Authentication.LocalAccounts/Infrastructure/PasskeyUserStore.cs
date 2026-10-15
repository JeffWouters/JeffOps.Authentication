using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.LocalAccounts.Application;
using Microsoft.AspNetCore.Identity;

namespace JeffOps.Authentication.LocalAccounts.Infrastructure;

/// <summary>
/// The narrow slice of an ASP.NET Core Identity user store that its WebAuthn ceremony (<see cref="PasskeyHandler{TUser}"/>)
/// needs: users by id or passkey, and their passkeys. Accounts and credentials stay in their own stores; nothing else of
/// Identity is used.
/// </summary>
internal sealed class PasskeyUserStore(IAccountRepository accounts, ILocalCredentialRepository credentials, ILocalUnitOfWork unitOfWork, TimeProvider time)
    : IUserPasskeyStore<PasskeyUser>
{
    public async Task<PasskeyUser?> FindByIdAsync(string userId, CancellationToken cancellationToken) =>
        Guid.TryParse(userId, out var id) && await accounts.FindAsync(id, cancellationToken).ConfigureAwait(false) is { CanAuthenticate: true } account
            ? new PasskeyUser { Id = account.Id.ToString(), Email = account.Email, DisplayName = account.DisplayName }
            : null;

    public async Task<PasskeyUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken) =>
        await accounts.FindByEmailAsync(normalizedUserName, cancellationToken).ConfigureAwait(false) is { CanAuthenticate: true } account
            ? new PasskeyUser { Id = account.Id.ToString(), Email = account.Email, DisplayName = account.DisplayName }
            : null;

    public async Task<PasskeyUser?> FindByPasskeyIdAsync(byte[] credentialId, CancellationToken cancellationToken) =>
        await credentials.FindByPasskeyAsync(credentialId, cancellationToken).ConfigureAwait(false) is { } credential
            ? await FindByIdAsync(credential.Id.ToString(), cancellationToken).ConfigureAwait(false)
            : null;

    public async Task<IList<UserPasskeyInfo>> GetPasskeysAsync(PasskeyUser user, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        var credential = await credentials.FindAsync(Guid.Parse(user.Id), cancellationToken).ConfigureAwait(false);
        return [.. (credential?.Passkeys ?? []).Select(ToInfo)];
    }

    public async Task<UserPasskeyInfo?> FindPasskeyAsync(PasskeyUser user, byte[] credentialId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        var credential = await credentials.FindAsync(Guid.Parse(user.Id), cancellationToken).ConfigureAwait(false);
        return credential?.FindPasskey(credentialId) is { } passkey ? ToInfo(passkey) : null;
    }

    public async Task AddOrUpdatePasskeyAsync(PasskeyUser user, UserPasskeyInfo passkey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(passkey);
        var credential = await credentials.FindAsync(Guid.Parse(user.Id), cancellationToken).ConfigureAwait(false);
        if (credential is null)
        {
            credential = Domain.LocalCredential.Create(Guid.Parse(user.Id), time.GetUtcNow());
            credentials.Add(credential);
        }

        credential.SavePasskey(passkey.CredentialId, passkey.PublicKey, passkey.Name, passkey.CreatedAt, passkey.SignCount, passkey.Transports,
            passkey.IsUserVerified, passkey.IsBackupEligible, passkey.IsBackedUp, passkey.AttestationObject, passkey.ClientDataJson, time.GetUtcNow());
    }

    public async Task RemovePasskeyAsync(PasskeyUser user, byte[] credentialId, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);
        (await credentials.FindAsync(Guid.Parse(user.Id), cancellationToken).ConfigureAwait(false))?.RemovePasskey(credentialId);
    }

    public Task<string> GetUserIdAsync(PasskeyUser user, CancellationToken cancellationToken) => Task.FromResult(user.Id);

    public Task<string?> GetUserNameAsync(PasskeyUser user, CancellationToken cancellationToken) => Task.FromResult<string?>(user.Email);

    public Task<string?> GetNormalizedUserNameAsync(PasskeyUser user, CancellationToken cancellationToken) => Task.FromResult<string?>(user.Email);

    public Task SetUserNameAsync(PasskeyUser user, string? userName, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task SetNormalizedUserNameAsync(PasskeyUser user, string? normalizedName, CancellationToken cancellationToken) => Task.CompletedTask;

    public Task<IdentityResult> CreateAsync(PasskeyUser user, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Accounts are created by the token server, not through Identity.");

    public async Task<IdentityResult> UpdateAsync(PasskeyUser user, CancellationToken cancellationToken)
    {
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        return IdentityResult.Success;
    }

    public Task<IdentityResult> DeleteAsync(PasskeyUser user, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Accounts are deleted by the token server, not through Identity.");

    public void Dispose()
    {
    }

    private static UserPasskeyInfo ToInfo(Domain.StoredPasskey passkey) =>
        new(passkey.CredentialId, passkey.PublicKey, passkey.CreatedAt, passkey.SignCount, passkey.Transports, passkey.IsUserVerified,
            passkey.IsBackupEligible, passkey.IsBackedUp, passkey.AttestationObject, passkey.ClientDataJson)
        {
            Name = passkey.Name,
        };
}

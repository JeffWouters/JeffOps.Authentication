using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Infrastructure.Keys;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// Puts the provider's keys into OpenIddict: every published signing key (JWKS), with the active signer first so it signs,
/// and the database encryption keys. Re-runs whenever <see cref="ITokenKeyProvider.KeysChanged"/> fires (I4).
/// </summary>
internal sealed class ServerCredentialsSetup(ITokenKeyProvider signing, DatabaseKeyStore encryption, TimeProvider time)
    : IConfigureOptions<OpenIddictServerOptions>
{
    public void Configure(OpenIddictServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var now = time.GetUtcNow();
        var keys = signing.GetSigningKeys();
        var active = keys.FirstOrDefault(key => key.ActivatesAt <= now) ?? keys.LastOrDefault()
            ?? throw new InvalidOperationException("The token key provider returned no signing keys.");

        // OpenIddict signs with the first signing credential; the others stay published for validation.
        foreach (var key in keys.Where(key => key != active).Prepend(active))
        {
            options.SigningCredentials.Add(new SigningCredentials(new RsaSecurityKey(key.Key) { KeyId = key.KeyId }, SecurityAlgorithms.RsaSha256));
        }

        foreach (var key in encryption.GetEncryptionKeys())
        {
            options.EncryptionCredentials.Add(new EncryptingCredentials(
                new RsaSecurityKey(key), SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512));
        }
    }
}

/// <summary>
/// Invalidates cached options when the keys change, so the next request rebuilds them: the server's credentials, and the
/// local validation that copies them.
/// </summary>
internal sealed class KeysChangeTokenSource<TOptions> : IOptionsChangeTokenSource<TOptions>, IDisposable
{
    private readonly ITokenKeyProvider _provider;
    private CancellationTokenSource _changed = new();

    public KeysChangeTokenSource(ITokenKeyProvider provider)
    {
        _provider = provider;
        _provider.KeysChanged += OnKeysChanged;
    }

    public string? Name => Options.DefaultName;

    public IChangeToken GetChangeToken() => new CancellationChangeToken(_changed.Token);

    public void Dispose()
    {
        _provider.KeysChanged -= OnKeysChanged;
        _changed.Dispose();
    }

    private void OnKeysChanged(object? sender, EventArgs e)
    {
        var previous = Interlocked.Exchange(ref _changed, new CancellationTokenSource());
        previous.Cancel();
        previous.Dispose();
    }
}

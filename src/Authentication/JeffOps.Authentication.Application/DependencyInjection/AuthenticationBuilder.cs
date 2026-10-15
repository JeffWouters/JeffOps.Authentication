using JeffOps.Authentication.Application.Abstractions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace JeffOps.Authentication.Application.DependencyInjection;

/// <summary>
/// Returned by <c>AddJeffOpsAuthentication</c>. Persistence packages and plug-ins (key providers, identity providers) add
/// extension methods to it, so a host composes the token server in one chain (docs/DESIGN.md §6.4).
/// </summary>
public sealed record AuthenticationBuilder(IServiceCollection Services, IConfiguration Configuration)
{
    /// <summary>Replaces the signing key provider, for example with Key Vault.</summary>
    public AuthenticationBuilder UseSigningKeyProvider<TProvider>()
        where TProvider : class, ITokenKeyProvider
    {
        Services.RemoveAll<ITokenKeyProvider>();
        Services.AddSingleton<ITokenKeyProvider, TProvider>();
        return this;
    }
}

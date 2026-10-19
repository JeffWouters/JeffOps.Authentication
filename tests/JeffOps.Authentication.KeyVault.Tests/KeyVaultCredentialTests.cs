using Azure.Core;
using Azure.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;

namespace JeffOps.Authentication.KeyVault.Tests;

public sealed class KeyVaultCredentialTests
{
    private static TokenCredential CredentialFor(string environment, TokenCredential? registered = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IHostEnvironment>(new HostingEnvironment { EnvironmentName = environment });
        if (registered is not null)
        {
            services.AddSingleton(registered);
        }

        using var provider = services.BuildServiceProvider();
        return KeyVaultKeyProvider.Credential(provider, new KeyVaultSigningOptions());
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public void Outside_development_a_managed_identity_is_used_never_the_default_chain(string environment) =>
        CredentialFor(environment).ShouldBeOfType<ManagedIdentityCredential>();

    [Fact]
    public void Development_may_use_the_developer_credential_chain() =>
        CredentialFor("Development").ShouldBeOfType<DefaultAzureCredential>();

    [Fact]
    public void A_registered_credential_wins_everywhere()
    {
        var registered = new ClientSecretCredential("tenant", "client", "not-a-real-secret");

        CredentialFor("Production", registered).ShouldBeSameAs(registered);
    }
}

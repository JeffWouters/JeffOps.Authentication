using JeffOps.Authentication.Application;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// Runs database initializers (for example migrations) and then creates or updates the configured scopes and clients
/// (docs/DESIGN.md §7.7). Clients follow configuration exactly: a grant removed from configuration is removed from the
/// client, and a client removed from configuration is deleted, with its authorizations and tokens.
/// </summary>
internal sealed class AuthenticationStartup(IServiceProvider services, IOptions<TokenServerOptions> options, IHostEnvironment environment) : IHostedService
{
    private const int MinimumSecretLength = 32;

    /// <summary>Words that mark a secret copied from a sample or development configuration (such as the reference host's).</summary>
    private static readonly string[] PlaceholderMarkers = ["development", "replace", "changeme", "change-me", "placeholder", "example"];

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = services.CreateAsyncScope();
        foreach (var initializer in scope.ServiceProvider.GetServices<IAuthenticationDatabaseInitializer>())
        {
            await initializer.InitializeAsync(cancellationToken).ConfigureAwait(false);
        }

        await SeedScopesAsync(scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>(), cancellationToken).ConfigureAwait(false);

        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        foreach (var client in options.Value.Clients)
        {
            await SeedClientAsync(applications, client, cancellationToken).ConfigureAwait(false);
        }

        await RemoveUnconfiguredClientsAsync(applications, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Deletes clients no longer configured: their redirect URIs may now belong to someone else, and their secrets and
    /// refresh tokens must stop working.
    /// </summary>
    private async Task RemoveUnconfiguredClientsAsync(IOpenIddictApplicationManager applications, CancellationToken cancellationToken)
    {
        var configured = options.Value.Clients.Select(client => client.ClientId).ToHashSet(StringComparer.Ordinal);
        var removed = new List<object>();
        await foreach (var application in applications.ListAsync(count: null, offset: null, cancellationToken).ConfigureAwait(false))
        {
            if (await applications.GetClientIdAsync(application, cancellationToken).ConfigureAwait(false) is not { } clientId || !configured.Contains(clientId))
            {
                removed.Add(application);
            }
        }

        foreach (var application in removed)
        {
            await applications.DeleteAsync(application, cancellationToken).ConfigureAwait(false);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private async Task SeedScopesAsync(IOpenIddictScopeManager scopes, CancellationToken cancellationToken)
    {
        var scopesToSeed = options.Value.ApiScopes
            .Select(pair => (pair.Key, (IEnumerable<string>)pair.Value))
            .Append((AccountApi.Scope, [options.Value.AccountAudience]));
        foreach (var (name, audiences) in scopesToSeed)
        {
            var descriptor = new OpenIddictScopeDescriptor { Name = name, DisplayName = name };
            foreach (var audience in audiences.Where(audience => !string.IsNullOrWhiteSpace(audience)))
            {
                descriptor.Resources.Add(audience);
            }

            if (await scopes.FindByNameAsync(name, cancellationToken).ConfigureAwait(false) is { } existing)
            {
                await scopes.UpdateAsync(existing, descriptor, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await scopes.CreateAsync(descriptor, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task SeedClientAsync(IOpenIddictApplicationManager applications, ClientDefinition client, CancellationToken cancellationToken)
    {
        var descriptor = Describe(client);
        var existing = await applications.FindByClientIdAsync(client.ClientId, cancellationToken).ConfigureAwait(false);
        if (existing is null)
        {
            await applications.CreateAsync(descriptor, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await applications.UpdateAsync(existing, descriptor, cancellationToken).ConfigureAwait(false);
        }
    }

    internal OpenIddictApplicationDescriptor Describe(ClientDefinition client)
    {
        if (string.IsNullOrWhiteSpace(client.ClientId))
        {
            throw new InvalidOperationException("Every configured client needs a ClientId.");
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = client.ClientId,
            DisplayName = client.DisplayName ?? client.ClientId,
            ClientType = client.Kind == ClientKind.Public ? ClientTypes.Public : ClientTypes.Confidential,
            ConsentType = ConsentTypes.Implicit,
        };

        if (!string.IsNullOrWhiteSpace(client.JsonWebKeySet))
        {
            descriptor.JsonWebKeySet = Microsoft.IdentityModel.Tokens.JsonWebKeySet.Create(client.JsonWebKeySet);
        }

        if (client.Kind == ClientKind.Confidential && (descriptor.JsonWebKeySet is null || !string.IsNullOrEmpty(client.ClientSecret)))
        {
            if (string.IsNullOrEmpty(client.ClientSecret))
            {
                throw new InvalidOperationException($"Confidential client '{client.ClientId}' needs a ClientSecret.");
            }

            if (!environment.IsDevelopment() && client.ClientSecret.Length < MinimumSecretLength)
            {
                throw new InvalidOperationException(
                    $"The secret of client '{client.ClientId}' is shorter than {MinimumSecretLength} characters. Outside Development, use a generated secret from the secret store.");
            }

            if (!environment.IsDevelopment() && PlaceholderMarkers.Any(marker => client.ClientSecret.Contains(marker, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException(
                    $"The secret of client '{client.ClientId}' is a placeholder from a sample or development configuration. Outside Development, use a generated secret from the secret store.");
            }

            descriptor.ClientSecret = client.ClientSecret;
        }

        foreach (var uri in client.RedirectUris)
        {
            descriptor.RedirectUris.Add(uri);
        }

        foreach (var uri in client.PostLogoutRedirectUris)
        {
            descriptor.PostLogoutRedirectUris.Add(uri);
        }

        var permissions = descriptor.Permissions;
        var grants = client.GrantTypes.Select(grant => grant.Trim()).ToHashSet(StringComparer.Ordinal);

        if (grants.Count > 0)
        {
            permissions.Add(Permissions.Endpoints.Token);
            permissions.Add(Permissions.Endpoints.Revocation);
        }

        if (grants.Contains(GrantTypes.AuthorizationCode))
        {
            permissions.Add(Permissions.Endpoints.Authorization);
            permissions.Add(Permissions.Endpoints.EndSession);
            permissions.Add(Permissions.GrantTypes.AuthorizationCode);
            permissions.Add(Permissions.ResponseTypes.Code);
            descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
        }

        foreach (var grant in grants.Where(grant => grant != GrantTypes.AuthorizationCode))
        {
            permissions.Add(Permissions.Prefixes.GrantType + grant);
        }

        if (grants.Contains(GrantTypes.DeviceCode))
        {
            permissions.Add(Permissions.Endpoints.DeviceAuthorization);
        }

        if (grants.Contains(GrantTypes.AuthorizationCode))
        {
            // Every code-flow client may push its requests (PAR); some must.
            permissions.Add(Permissions.Endpoints.PushedAuthorization);
            if (client.RequirePushedAuthorization)
            {
                descriptor.Requirements.Add(Requirements.Features.PushedAuthorizationRequests);
            }
        }

        foreach (var scopeName in client.Scopes.Where(scopeName => !string.IsNullOrWhiteSpace(scopeName)).Select(scopeName => scopeName.Trim()))
        {
            permissions.Add(scopeName switch
            {
                Scopes.Email => Permissions.Scopes.Email,
                Scopes.Profile => Permissions.Scopes.Profile,
                Scopes.OpenId => Permissions.Prefixes.Scope + Scopes.OpenId,
                _ => Permissions.Prefixes.Scope + scopeName,
            });
        }

        return descriptor;
    }
}

/// <summary>Prepares the database before clients are seeded, for example by applying migrations.</summary>
public interface IAuthenticationDatabaseInitializer
{
    /// <summary>Brings the database up to date. Runs once at startup, before clients and scopes are seeded.</summary>
    Task InitializeAsync(CancellationToken cancellationToken);
}

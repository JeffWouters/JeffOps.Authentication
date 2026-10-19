using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using OpenIddict.EntityFrameworkCore;
using OpenIddict.EntityFrameworkCore.Models;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// The configured clients, as last read, shared by every request for <see cref="Lifetime"/>. Clients change only when the
/// configuration does (they are seeded at startup), and every request otherwise read its client from the database.
/// </summary>
internal sealed class ClientSnapshots(TimeProvider time)
{
    /// <summary>How long a snapshot is used before the client is read again (the bound on staleness across instances).</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(60);

    private readonly ConcurrentDictionary<string, (Snapshot Client, DateTimeOffset ReadAt)> _byClientId = new(StringComparer.Ordinal);

    public Snapshot? Find(string clientId) =>
        _byClientId.TryGetValue(clientId, out var entry) && time.GetUtcNow() - entry.ReadAt < Lifetime ? entry.Client : null;

    public void Remember(OpenIddictEntityFrameworkCoreApplication application)
    {
        if (application.ClientId is { } clientId)
        {
            _byClientId[clientId] = (Snapshot.Of(application), time.GetUtcNow());
        }
    }

    public void Forget(string? clientId)
    {
        if (clientId is not null)
        {
            _byClientId.TryRemove(clientId, out _);
        }
    }

    /// <summary>The stored values of a client: copied out, so no entity instance is shared between requests.</summary>
    public sealed record Snapshot(
        string? Id, string? ApplicationType, string? ClientId, string? ClientSecret, string? ClientType, string? ConcurrencyToken, string? ConsentType,
        string? DisplayName, string? DisplayNames, string? JsonWebKeySet, string? Permissions, string? PostLogoutRedirectUris, string? Properties,
        string? RedirectUris, string? Requirements, string? Settings)
    {
        public static Snapshot Of(OpenIddictEntityFrameworkCoreApplication application) => new(
            application.Id, application.ApplicationType, application.ClientId, application.ClientSecret, application.ClientType, application.ConcurrencyToken,
            application.ConsentType, application.DisplayName, application.DisplayNames, application.JsonWebKeySet, application.Permissions,
            application.PostLogoutRedirectUris, application.Properties, application.RedirectUris, application.Requirements, application.Settings);

        public OpenIddictEntityFrameworkCoreApplication Materialize() => new()
        {
            Id = Id, ApplicationType = ApplicationType, ClientId = ClientId, ClientSecret = ClientSecret, ClientType = ClientType,
            ConcurrencyToken = ConcurrencyToken, ConsentType = ConsentType, DisplayName = DisplayName, DisplayNames = DisplayNames,
            JsonWebKeySet = JsonWebKeySet, Permissions = Permissions, PostLogoutRedirectUris = PostLogoutRedirectUris, Properties = Properties,
            RedirectUris = RedirectUris, Requirements = Requirements, Settings = Settings,
        };
    }
}

/// <summary>
/// OpenIddict's application store, reading a client by id from <see cref="ClientSnapshots"/> when it was read in the last
/// minute: the copy is attached to this request's context (unchanged), so OpenIddict and the token store find it there
/// and nothing is read. Every write goes to the database and drops the snapshot. A client id that isn't configured is never
/// found, even while the database still holds it (another replica, or before startup removed it).
/// </summary>
internal sealed class CachedApplicationStore(
    IMemoryCache cache,
    IOpenIddictEntityFrameworkCoreContext context,
    IOptionsMonitor<OpenIddictEntityFrameworkCoreOptions> options,
    IOptions<JeffOps.Authentication.Application.TokenServerOptions> tokenServer,
    ClientSnapshots snapshots) : OpenIddictEntityFrameworkCoreApplicationStore(cache, context, options)
{
    public override async ValueTask<OpenIddictEntityFrameworkCoreApplication?> FindByClientIdAsync(string identifier, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(identifier);
        if (JeffOps.Authentication.Application.Federation.ClientProviders.Find(tokenServer.Value, identifier) is null)
        {
            return null;
        }
        var db = await Context.GetDbContextAsync(cancellationToken).ConfigureAwait(false);
        if (snapshots.Find(identifier) is { } snapshot)
        {
            // Already in this context (an earlier lookup in the same request): that instance, never a second one.
            if (db.ChangeTracker.Entries<OpenIddictEntityFrameworkCoreApplication>().FirstOrDefault(entry => entry.Entity.Id == snapshot.Id) is { } tracked)
            {
                return tracked.Entity;
            }

            var application = snapshot.Materialize();
            db.Attach(application);
            return application;
        }

        var found = await base.FindByClientIdAsync(identifier, cancellationToken).ConfigureAwait(false);
        if (found is not null)
        {
            snapshots.Remember(found);
        }

        return found;
    }

    public override async ValueTask CreateAsync(OpenIddictEntityFrameworkCoreApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        snapshots.Forget(application.ClientId);
        await base.CreateAsync(application, cancellationToken).ConfigureAwait(false);
    }

    public override async ValueTask UpdateAsync(OpenIddictEntityFrameworkCoreApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        snapshots.Forget(application.ClientId);
        await base.UpdateAsync(application, cancellationToken).ConfigureAwait(false);
        snapshots.Forget(application.ClientId);
    }

    public override async ValueTask DeleteAsync(OpenIddictEntityFrameworkCoreApplication application, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(application);
        snapshots.Forget(application.ClientId);
        await base.DeleteAsync(application, cancellationToken).ConfigureAwait(false);
    }
}

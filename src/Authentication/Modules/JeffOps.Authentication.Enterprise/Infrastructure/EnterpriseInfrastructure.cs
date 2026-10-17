using System.Net.Http.Json;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Enterprise.Application;
using JeffOps.Authentication.Enterprise.Application.Features.Domains;
using JeffOps.Authentication.Enterprise.Application.Features.Providers;
using JeffOps.Authentication.Enterprise.Application.Features.Scim;
using JeffOps.Authentication.Enterprise.Application.Features.ScimTokens;
using JeffOps.Authentication.Enterprise.Application.Features.Sso;
using JeffOps.Authentication.Enterprise.Domain;
using JeffOps.Authentication.SharedKernel.DependencyInjection;
using JeffOps.Authentication.SharedKernel.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Enterprise.Infrastructure;

/// <summary>The enterprise store (schema <c>enterprise</c>). Provider-neutral; SQL Server migrations ship separately.</summary>
public sealed class EnterpriseDbContext(DbContextOptions<EnterpriseDbContext> options) : DbContext(options)
{
    public const string Schema = "enterprise";

    public DbSet<TenantDomain> Domains => Set<TenantDomain>();

    public DbSet<SsoPolicy> SsoPolicies => Set<SsoPolicy>();

    public DbSet<TenantIdentityProvider> IdentityProviders => Set<TenantIdentityProvider>();

    public DbSet<ScimToken> ScimTokens => Set<ScimToken>();

    public DbSet<ScimUser> ScimUsers => Set<ScimUser>();

    public DbSet<ScimGroup> ScimGroups => Set<ScimGroup>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        modelBuilder.HasDefaultSchema(Schema);

        modelBuilder.Entity<TenantDomain>(domain =>
        {
            domain.ToTable("TenantDomains");
            domain.HasKey(entity => entity.Id);
            domain.Property(entity => entity.Id).ValueGeneratedNever();
            domain.Property(entity => entity.Domain).HasMaxLength(253).IsRequired();
            domain.Property(entity => entity.VerificationToken).HasMaxLength(64);
            domain.Property(entity => entity.Status).HasConversion<string>().HasMaxLength(20);
            domain.HasIndex(entity => new { entity.TenantId, entity.Domain }).IsUnique();
            domain.HasIndex(entity => new { entity.Domain, entity.Status });
            domain.Ignore(entity => entity.DomainEvents);
        });

        modelBuilder.Entity<TenantIdentityProvider>(provider =>
        {
            provider.ToTable("TenantIdentityProviders");
            provider.HasKey(entity => entity.Id);
            provider.Property(entity => entity.Id).ValueGeneratedNever();
            provider.Property(entity => entity.DisplayName).HasMaxLength(100).IsRequired();
            provider.Property(entity => entity.EntityId).HasMaxLength(512).IsRequired();
            provider.Property(entity => entity.MetadataUrl).HasMaxLength(2048);
            provider.Property(entity => entity.SingleSignOnUrl).HasMaxLength(2048);
            provider.Property(entity => entity.SingleLogoutUrl).HasMaxLength(2048);
            provider.HasIndex(entity => entity.TenantId);
            provider.Ignore(entity => entity.Name);
            provider.Ignore(entity => entity.CertificateList);
            provider.Ignore(entity => entity.MultiFactorAuthnContextList);
        });

        modelBuilder.Entity<SsoPolicy>(policy =>
        {
            policy.ToTable("SsoPolicies");
            policy.HasKey(entity => entity.TenantId);
            policy.Property(entity => entity.Provider).HasMaxLength(100);
            policy.Property(entity => entity.CustomProvidersAllowed).HasDefaultValue(false);
        });

        modelBuilder.Entity<ScimToken>(token =>
        {
            token.ToTable("ScimTokens");
            token.HasKey(entity => entity.Id);
            token.Property(entity => entity.Name).HasMaxLength(100);
            token.Property(entity => entity.TokenHash).HasMaxLength(64);
            token.HasIndex(entity => entity.TokenHash).IsUnique();
            token.HasIndex(entity => entity.TenantId);
            token.Ignore(entity => entity.IsActive);
        });

        modelBuilder.Entity<ScimUser>(user =>
        {
            user.ToTable("ScimUsers");
            user.HasKey(entity => new { entity.TenantId, entity.AccountId });
            user.Property(entity => entity.UserName).HasMaxLength(256).IsRequired();
            user.Property(entity => entity.ExternalId).HasMaxLength(256);
            user.Property(entity => entity.GivenName).HasMaxLength(200);
            user.Property(entity => entity.FamilyName).HasMaxLength(200);
            user.Property(entity => entity.DisplayName).HasMaxLength(300);
            user.Property(entity => entity.Version).IsConcurrencyToken();
            user.HasIndex(entity => new { entity.TenantId, entity.UserName }).IsUnique();
            user.HasIndex(entity => new { entity.TenantId, entity.ExternalId });
        });

        modelBuilder.Entity<ScimGroup>(group =>
        {
            group.ToTable("ScimGroups");
            group.HasKey(entity => entity.Id);
            group.Property(entity => entity.Id).ValueGeneratedNever();
            group.Property(entity => entity.DisplayName).HasMaxLength(256).IsRequired();
            group.Property(entity => entity.ExternalId).HasMaxLength(256);
            group.Property(entity => entity.Version).IsConcurrencyToken();
            group.HasIndex(entity => new { entity.TenantId, entity.DisplayName }).IsUnique();
            group.Ignore(entity => entity.MemberIds);
            group.OwnsMany(entity => entity.Members, member =>
            {
                member.ToTable("ScimGroupMembers");
                member.WithOwner().HasForeignKey(entity => entity.GroupId);
                member.HasKey(entity => new { entity.GroupId, entity.AccountId });

                // A key the domain sets: never generated, or EF takes a new member for an existing one and doesn't insert it.
                member.Property(entity => entity.AccountId).ValueGeneratedNever();
                member.HasIndex(entity => entity.AccountId);
            });
            group.Navigation(entity => entity.Members).HasField("_members").UsePropertyAccessMode(PropertyAccessMode.Field);
        });
    }
}

internal sealed class TenantDomainRepository(EnterpriseDbContext db) : ITenantDomainRepository
{
    public Task<TenantDomain?> FindAsync(Guid domainId, CancellationToken cancellationToken) =>
        db.Domains.FirstOrDefaultAsync(domain => domain.Id == domainId, cancellationToken);

    public async Task<IReadOnlyList<TenantDomain>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        await db.Domains.Where(domain => domain.TenantId == tenantId).OrderBy(domain => domain.Domain).ToListAsync(cancellationToken).ConfigureAwait(false);

    public Task<TenantDomain?> FindVerifiedAsync(string domain, CancellationToken cancellationToken) =>
        db.Domains.FirstOrDefaultAsync(candidate => candidate.Domain == domain && candidate.Status == DomainStatus.Verified, cancellationToken);

    public void Add(TenantDomain domain) => db.Domains.Add(domain);

    public void Remove(TenantDomain domain) => db.Domains.Remove(domain);
}

internal sealed class TenantIdentityProviderRepository(EnterpriseDbContext db) : ITenantIdentityProviderRepository
{
    public Task<TenantIdentityProvider?> FindAsync(Guid providerId, CancellationToken cancellationToken) =>
        db.IdentityProviders.FirstOrDefaultAsync(provider => provider.Id == providerId, cancellationToken);

    public async Task<IReadOnlyList<TenantIdentityProvider>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        await db.IdentityProviders.Where(provider => provider.TenantId == tenantId).OrderBy(provider => provider.DisplayName).ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(TenantIdentityProvider provider) => db.IdentityProviders.Add(provider);

    public void Remove(TenantIdentityProvider provider) => db.IdentityProviders.Remove(provider);
}

internal sealed class SsoPolicyRepository(EnterpriseDbContext db) : ISsoPolicyRepository
{
    public Task<SsoPolicy?> FindAsync(Guid tenantId, CancellationToken cancellationToken) =>
        db.SsoPolicies.FirstOrDefaultAsync(policy => policy.TenantId == tenantId, cancellationToken);

    public void Add(SsoPolicy policy) => db.SsoPolicies.Add(policy);
}

internal sealed class EnterpriseUnitOfWork(EnterpriseDbContext db, IDomainEventDispatcher dispatcher) : IEnterpriseUnitOfWork
{
    public async Task SaveChangesAsync(CancellationToken cancellationToken)
    {
        var aggregates = db.ChangeTracker.Entries<IHasDomainEvents>().Select(entry => entry.Entity).Where(entity => entity.DomainEvents.Count > 0).ToList();
        var events = aggregates.SelectMany(aggregate => aggregate.DomainEvents).ToList();
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        foreach (var aggregate in aggregates)
        {
            aggregate.ClearDomainEvents();
        }

        await dispatcher.DispatchAsync(events, cancellationToken).ConfigureAwait(false);
    }
}

internal sealed class ScimTokenRepository(EnterpriseDbContext db) : IScimTokenRepository
{
    public Task<ScimToken?> FindByHashAsync(string hash, CancellationToken cancellationToken) =>
        db.ScimTokens.FirstOrDefaultAsync(token => token.TokenHash == hash, cancellationToken);

    public Task<ScimToken?> FindAsync(Guid tokenId, CancellationToken cancellationToken) =>
        db.ScimTokens.FirstOrDefaultAsync(token => token.Id == tokenId, cancellationToken);

    public async Task<IReadOnlyList<ScimToken>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        await db.ScimTokens.Where(token => token.TenantId == tenantId).ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(ScimToken token) => db.ScimTokens.Add(token);
}

internal sealed class ScimUserRepository(EnterpriseDbContext db) : IScimUserRepository
{
    public Task<ScimUser?> FindAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken) =>
        db.ScimUsers.FirstOrDefaultAsync(user => user.TenantId == tenantId && user.AccountId == accountId, cancellationToken);

    public async Task<(IReadOnlyList<ScimUser> Page, int Total)> ListAsync(Guid tenantId, ScimFilter? filter, int skip, int take, CancellationToken cancellationToken)
    {
        var query = db.ScimUsers.Where(user => user.TenantId == tenantId);
        if (filter is { Attribute: "userName" })
        {
            // SCIM userName is case-insensitive (RFC 7643 section 4.1.1).
            var value = filter.Value.ToLowerInvariant();
            query = query.Where(user => user.UserName.ToLower() == value);
        }
        else if (filter is { Attribute: "externalId" })
        {
            query = query.Where(user => user.ExternalId == filter.Value);
        }

        var total = await query.CountAsync(cancellationToken).ConfigureAwait(false);
        var page = await query.OrderBy(user => user.UserName).Skip(skip).Take(take).ToListAsync(cancellationToken).ConfigureAwait(false);
        return (page, total);
    }

    public async Task<IReadOnlyList<ScimUser>> FindManyAsync(Guid tenantId, IReadOnlyCollection<Guid> accountIds, CancellationToken cancellationToken) =>
        accountIds.Count == 0
            ? []
            : await db.ScimUsers.Where(user => user.TenantId == tenantId && accountIds.Contains(user.AccountId)).ToListAsync(cancellationToken).ConfigureAwait(false);

    public Task<bool> ProvisionedElsewhereAsync(Guid accountId, Guid tenantId, CancellationToken cancellationToken) =>
        db.ScimUsers.AnyAsync(user => user.AccountId == accountId && user.TenantId != tenantId, cancellationToken);

    public void Add(ScimUser user) => db.ScimUsers.Add(user);

    public void Remove(ScimUser user) => db.ScimUsers.Remove(user);
}

internal sealed class ScimGroupRepository(EnterpriseDbContext db) : IScimGroupRepository
{
    public Task<ScimGroup?> FindAsync(Guid tenantId, Guid groupId, CancellationToken cancellationToken) =>
        db.ScimGroups.FirstOrDefaultAsync(group => group.TenantId == tenantId && group.Id == groupId, cancellationToken);

    public async Task<(IReadOnlyList<ScimGroup> Page, int Total)> ListAsync(Guid tenantId, ScimFilter? filter, int skip, int take, CancellationToken cancellationToken)
    {
        var query = db.ScimGroups.Where(group => group.TenantId == tenantId);
        if (filter is { Attribute: "displayName" })
        {
            var value = filter.Value.ToLowerInvariant();
            query = query.Where(group => group.DisplayName.ToLower() == value);
        }
        else if (filter is { Attribute: "externalId" })
        {
            query = query.Where(group => group.ExternalId == filter.Value);
        }

        var total = await query.CountAsync(cancellationToken).ConfigureAwait(false);
        var page = await query.OrderBy(group => group.DisplayName).Skip(skip).Take(take).ToListAsync(cancellationToken).ConfigureAwait(false);
        return (page, total);
    }

    public async Task<IReadOnlyList<ScimGroup>> ListForMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken) =>
        await db.ScimGroups.Where(group => group.TenantId == tenantId && group.Members.Any(member => member.AccountId == accountId)).ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(ScimGroup group) => db.ScimGroups.Add(group);

    public void Remove(ScimGroup group) => db.ScimGroups.Remove(group);
}

/// <summary>Reads TXT records with DNS over HTTPS (RFC 8484 JSON API, as Cloudflare and Google serve it).</summary>
internal sealed class DnsOverHttpsResolver(IHttpClientFactory http, IOptions<EnterpriseOptions> options) : IDnsTxtResolver
{
    public const string HttpClientName = "JeffOps.Enterprise.Dns";

    public async Task<IReadOnlyList<string>> ResolveTxtAsync(string name, CancellationToken cancellationToken)
    {
        using var client = http.CreateClient(HttpClientName);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"{options.Value.DnsOverHttpsEndpoint}?name={Uri.EscapeDataString(name)}&type=TXT"));
        request.Headers.Accept.ParseAdd("application/dns-json");
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var answer = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken).ConfigureAwait(false);
        if (!answer.TryGetProperty("Answer", out var records) || records.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        // TXT data arrives quoted, long values split in several quoted strings: join them.
        return [.. records.EnumerateArray()
            .Where(record => record.TryGetProperty("type", out var type) && type.GetInt32() == 16)
            .Select(record => string.Concat(record.GetProperty("data").GetString()!.Split('"', StringSplitOptions.RemoveEmptyEntries).Where(part => part.Trim().Length > 0)))];
    }
}

/// <summary>Returned by <see cref="EnterpriseServiceCollectionExtensions.AddEnterprise"/>.</summary>
public sealed record EnterpriseBuilder(IServiceCollection Services)
{
    public EnterpriseBuilder UseDatabase(Action<IServiceProvider, DbContextOptionsBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.AddDbContext<EnterpriseDbContext>(configure);
        return this;
    }

    public EnterpriseBuilder UseDnsResolver<TResolver>()
        where TResolver : class, IDnsTxtResolver
    {
        Services.RemoveAll<IDnsTxtResolver>();
        Services.AddScoped<IDnsTxtResolver, TResolver>();
        return this;
    }
}

/// <summary>Prepares the enterprise database, for example by applying migrations.</summary>
public interface IEnterpriseDatabaseInitializer
{
    Task InitializeAsync(CancellationToken cancellationToken);
}

public static class EnterpriseServiceCollectionExtensions
{
    /// <summary>
    /// Adds enterprise features (docs/DESIGN.md §8.4): tenants verify their email domains by DNS, choose the identity provider
    /// their members sign in with, and can make it the only way in. Home realm discovery and every sign-in method respect it.
    /// Map the endpoints with <c>MapJeffOpsEnterprise</c>.
    /// </summary>
    public static EnterpriseBuilder AddEnterprise(this AuthenticationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.Services.AddJeffOpsEnterprise(builder.Configuration);
    }

    /// <summary>The registrations behind <see cref="AddEnterprise"/>.</summary>
    public static EnterpriseBuilder AddJeffOpsEnterprise(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<EnterpriseOptions>().Bind(configuration.GetSection(EnterpriseOptions.SectionName));
        services.TryAddScoped<ITenantDomainRepository, TenantDomainRepository>();
        services.TryAddScoped<ISsoPolicyRepository, SsoPolicyRepository>();
        services.TryAddScoped<ITenantIdentityProviderRepository, TenantIdentityProviderRepository>();
        services.TryAddScoped<IEnterpriseUnitOfWork, EnterpriseUnitOfWork>();
        services.TryAddScoped<IDnsTxtResolver, DnsOverHttpsResolver>();
        services.AddHttpClient(DnsOverHttpsResolver.HttpClientName);
        services.TryAddScoped<IScimTokenRepository, ScimTokenRepository>();
        services.TryAddScoped<IScimUserRepository, ScimUserRepository>();
        services.TryAddScoped<IScimGroupRepository, ScimGroupRepository>();
        services.TryAddScoped<ITenantMembershipProvisioner, NoMembershipProvisioning>();
        services.TryAddScoped<ScimProvisioning>();
        services.TryAddScoped<ScimTokenAuthenticator>();

        services.RemoveAll<IHomeRealmDirectory>();
        services.AddScoped<IHomeRealmDirectory, EnterpriseHomeRealms>();
        services.AddScoped<IProvisionedAccountDirectory, ScimProvisionedAccounts>();
        services.AddScoped<ITenantProviderDirectory, EnterpriseTenantProviders>();

        services
            .AddHandler<ClaimDomainHandler>()
            .AddHandler<VerifyDomainHandler>()
            .AddHandler<ListDomainsHandler>()
            .AddHandler<RemoveDomainHandler>()
            .AddHandler<GetSsoPolicyHandler>()
            .AddHandler<SetSsoPolicyHandler>()
            .AddHandler<ListTenantProvidersHandler>()
            .AddHandler<SaveTenantProviderHandler>()
            .AddHandler<DeleteTenantProviderHandler>()
            .AddHandler<SetCustomProvidersAllowedHandler>()
            .AddHandler<CreateScimTokenHandler>()
            .AddHandler<ListScimTokensHandler>()
            .AddHandler<RevokeScimTokenHandler>()
            .AddHandler<CreateScimUserHandler>()
            .AddHandler<UpdateScimUserHandler>()
            .AddHandler<DeleteScimUserHandler>()
            .AddHandler<GetScimUserHandler>()
            .AddHandler<ListScimUsersHandler>()
            .AddHandler<CreateScimGroupHandler>()
            .AddHandler<UpdateScimGroupHandler>()
            .AddHandler<DeleteScimGroupHandler>()
            .AddHandler<GetScimGroupHandler>()
            .AddHandler<ListScimGroupsHandler>();

        services.AddHostedService<EnterpriseStartup>();
        return new EnterpriseBuilder(services);
    }
}

internal sealed class EnterpriseStartup(IServiceProvider services) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = services.CreateAsyncScope();
        foreach (var initializer in scope.ServiceProvider.GetServices<IEnterpriseDatabaseInitializer>())
        {
            await initializer.InitializeAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

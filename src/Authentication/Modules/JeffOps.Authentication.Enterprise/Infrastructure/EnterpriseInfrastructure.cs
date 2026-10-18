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
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
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

    public DbSet<TenantOidcIdentityProvider> OidcProviders => Set<TenantOidcIdentityProvider>();

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

        modelBuilder.Entity<TenantOidcIdentityProvider>(provider =>
        {
            provider.ToTable("TenantOidcProviders");
            provider.HasKey(entity => entity.Id);
            provider.Property(entity => entity.Id).ValueGeneratedNever();
            provider.Property(entity => entity.DisplayName).HasMaxLength(100).IsRequired();
            provider.Property(entity => entity.Issuer).HasMaxLength(512).IsRequired();
            provider.Property(entity => entity.ClientId).HasMaxLength(256).IsRequired();
            provider.Property(entity => entity.Scopes).HasMaxLength(1024).IsRequired();
            provider.HasIndex(entity => entity.TenantId);
            provider.Ignore(entity => entity.Name);
            provider.Ignore(entity => entity.ScopeList);
            provider.Ignore(entity => entity.MultiFactorAcrValueList);
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

        // SCIM's externalId is case-exact (RFC 7643 §3.1); SQL Server compares case-insensitively unless told otherwise.
        if (Database.ProviderName == "Microsoft.EntityFrameworkCore.SqlServer")
        {
            modelBuilder.Entity<ScimUser>().Property(entity => entity.ExternalId).UseCollation("Latin1_General_100_BIN2");
            modelBuilder.Entity<ScimGroup>().Property(entity => entity.ExternalId).UseCollation("Latin1_General_100_BIN2");
        }

        // SQLite can't order or compare DateTimeOffset values (SCIM sorts and filters by meta timestamps): there, store them
        // as order-preserving integers. Other databases keep their own timestamp type.
        if (Database.ProviderName == "Microsoft.EntityFrameworkCore.Sqlite")
        {
            var converter = new Microsoft.EntityFrameworkCore.Storage.ValueConversion.DateTimeOffsetToBinaryConverter();
            foreach (var property in modelBuilder.Model.GetEntityTypes().SelectMany(entity => entity.GetProperties())
                .Where(property => property.ClrType == typeof(DateTimeOffset) || property.ClrType == typeof(DateTimeOffset?)))
            {
                property.SetValueConverter(converter);
            }
        }
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

internal sealed class TenantOidcProviderRepository(EnterpriseDbContext db) : ITenantOidcProviderRepository
{
    public Task<TenantOidcIdentityProvider?> FindAsync(Guid providerId, CancellationToken cancellationToken) =>
        db.OidcProviders.FirstOrDefaultAsync(provider => provider.Id == providerId, cancellationToken);

    public async Task<IReadOnlyList<TenantOidcIdentityProvider>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        await db.OidcProviders.Where(provider => provider.TenantId == tenantId).OrderBy(provider => provider.DisplayName).ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(TenantOidcIdentityProvider provider) => db.OidcProviders.Add(provider);

    public void Remove(TenantOidcIdentityProvider provider) => db.OidcProviders.Remove(provider);
}

/// <summary>Client secrets encrypted with the Data Protection key ring the token server already shares between instances.</summary>
internal sealed class DataProtectionClientSecrets(IDataProtectionProvider dataProtection) : IClientSecretProtector
{
    private readonly IDataProtector _protector = dataProtection.CreateProtector("JeffOps.Enterprise.TenantOidcClientSecret.v1");

    public string Protect(string secret) => _protector.Protect(secret);

    public string? Unprotect(string protectedSecret)
    {
        try
        {
            return _protector.Unprotect(protectedSecret);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}

internal sealed class SsoPolicyRepository(EnterpriseDbContext db) : ISsoPolicyRepository
{
    public Task<SsoPolicy?> FindAsync(Guid tenantId, CancellationToken cancellationToken) =>
        db.SsoPolicies.FirstOrDefaultAsync(policy => policy.TenantId == tenantId, cancellationToken);

    public void Add(SsoPolicy policy) => db.SsoPolicies.Add(policy);
}

internal sealed class EnterpriseUnitOfWork(EnterpriseDbContext db, IDomainEventDispatcher dispatcher) : IEnterpriseUnitOfWork
{
    public async Task<bool> TrySaveChangesAsync(CancellationToken cancellationToken)
    {
        try
        {
            await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (DbUpdateConcurrencyException)
        {
            db.ChangeTracker.Clear();
            return false;
        }
    }

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

    public async Task<(IReadOnlyList<ScimUser> Page, int Total)> ListAsync(
        Guid tenantId, System.Linq.Expressions.Expression<Func<ScimUser, bool>>? filter, int skip, int take, ScimSort? sort, CancellationToken cancellationToken)
    {
        var query = db.ScimUsers.Where(user => user.TenantId == tenantId);
        if (filter is not null)
        {
            query = query.Where(filter);
        }

        var total = await query.CountAsync(cancellationToken).ConfigureAwait(false);
        var ordered = (sort?.Attribute, sort?.Descending ?? false) switch
        {
            ("externalId", var descending) => ScimOrder.By(query, user => user.ExternalId == null, user => user.ExternalId!.ToLower(), descending),
            ("displayName", var descending) => ScimOrder.By(query, user => user.DisplayName == null, user => user.DisplayName!.ToLower(), descending),
            ("name.givenName", var descending) => ScimOrder.By(query, user => user.GivenName == null, user => user.GivenName!.ToLower(), descending),
            ("name.familyName", var descending) => ScimOrder.By(query, user => user.FamilyName == null, user => user.FamilyName!.ToLower(), descending),
            ("meta.created", false) => query.OrderBy(user => user.Created),
            ("meta.created", true) => query.OrderByDescending(user => user.Created),
            ("meta.lastModified", false) => query.OrderBy(user => user.LastModified),
            ("meta.lastModified", true) => query.OrderByDescending(user => user.LastModified),
            (_, true) => query.OrderByDescending(user => user.UserName.ToLower()),
            _ => query.OrderBy(user => user.UserName.ToLower()),
        };
        var page = await ordered.ThenBy(user => user.AccountId).Skip(skip).Take(take).ToListAsync(cancellationToken).ConfigureAwait(false);
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

/// <summary>SCIM list order: resources without a value last ascending and first descending (RFC 7644 §3.4.2.3).</summary>
internal static class ScimOrder
{
    public static IOrderedQueryable<T> By<T>(IQueryable<T> query, System.Linq.Expressions.Expression<Func<T, bool>> missing, System.Linq.Expressions.Expression<Func<T, string>> key, bool descending) =>
        descending ? query.OrderByDescending(missing).ThenByDescending(key) : query.OrderBy(missing).ThenBy(key);
}

internal sealed class ScimGroupRepository(EnterpriseDbContext db) : IScimGroupRepository
{
    public Task<ScimGroup?> FindAsync(Guid tenantId, Guid groupId, CancellationToken cancellationToken) =>
        db.ScimGroups.FirstOrDefaultAsync(group => group.TenantId == tenantId && group.Id == groupId, cancellationToken);

    public async Task<(IReadOnlyList<ScimGroup> Page, int Total)> ListAsync(
        Guid tenantId, System.Linq.Expressions.Expression<Func<ScimGroup, bool>>? filter, int skip, int take, ScimSort? sort, CancellationToken cancellationToken)
    {
        var query = db.ScimGroups.Where(group => group.TenantId == tenantId);
        if (filter is not null)
        {
            query = query.Where(filter);
        }

        var total = await query.CountAsync(cancellationToken).ConfigureAwait(false);
        var page = await Ordered(query, sort).Skip(skip).Take(take).ToListAsync(cancellationToken).ConfigureAwait(false);
        return (page, total);
    }

    public async Task<(IReadOnlyList<ScimGroupView> Page, int Total)> ListWithoutMembersAsync(
        Guid tenantId, System.Linq.Expressions.Expression<Func<ScimGroup, bool>>? filter, int skip, int take, ScimSort? sort, CancellationToken cancellationToken)
    {
        var query = db.ScimGroups.Where(group => group.TenantId == tenantId);
        if (filter is not null)
        {
            query = query.Where(filter);
        }

        var total = await query.CountAsync(cancellationToken).ConfigureAwait(false);

        // A projection: the members (an owned collection, loaded with every group otherwise) aren't read.
        var page = await Ordered(query, sort).Skip(skip).Take(take)
            .Select(group => new { group.Id, group.DisplayName, group.ExternalId, group.Created, group.LastModified, group.Version })
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return ([.. page.Select(group => new ScimGroupView(group.Id, group.DisplayName, group.ExternalId, [], group.Created, group.LastModified, group.Version))], total);
    }

    private static IOrderedQueryable<ScimGroup> Ordered(IQueryable<ScimGroup> query, ScimSort? sort) =>
        ((sort?.Attribute, sort?.Descending ?? false) switch
        {
            ("externalId", var descending) => ScimOrder.By(query, group => group.ExternalId == null, group => group.ExternalId!.ToLower(), descending),
            ("meta.created", false) => query.OrderBy(group => group.Created),
            ("meta.created", true) => query.OrderByDescending(group => group.Created),
            ("meta.lastModified", false) => query.OrderBy(group => group.LastModified),
            ("meta.lastModified", true) => query.OrderByDescending(group => group.LastModified),
            (_, true) => query.OrderByDescending(group => group.DisplayName.ToLower()),
            _ => query.OrderBy(group => group.DisplayName.ToLower()),
        }).ThenBy(group => group.Id);

    public async Task<IReadOnlyList<(Guid AccountId, Guid GroupId, string DisplayName)>> ListMembershipsAsync(
        Guid tenantId, IReadOnlyCollection<Guid> accountIds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(accountIds);
        if (accountIds.Count == 0)
        {
            return [];
        }

        var rows = await db.ScimGroups
            .Where(group => group.TenantId == tenantId)
            .SelectMany(group => group.Members.Where(member => accountIds.Contains(member.AccountId)), (group, member) => new { member.AccountId, group.Id, group.DisplayName })
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return [.. rows.OrderBy(row => row.DisplayName, StringComparer.OrdinalIgnoreCase).Select(row => (row.AccountId, row.Id, row.DisplayName))];
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
        services.TryAddScoped<ITenantOidcProviderRepository, TenantOidcProviderRepository>();
        services.AddDataProtection();
        services.TryAddSingleton<IClientSecretProtector, DataProtectionClientSecrets>();
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
            .AddHandler<ListTenantOidcProvidersHandler>()
            .AddHandler<SaveTenantOidcProviderHandler>()
            .AddHandler<DeleteTenantOidcProviderHandler>()
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
            .AddHandler<ListScimGroupsHandler>()
            .AddHandler<SearchScimHandler>();

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

using System.Net.Http.Json;
using System.Text.Json;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Enterprise.Application;
using JeffOps.Authentication.Enterprise.Application.Features.Domains;
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

        modelBuilder.Entity<SsoPolicy>(policy =>
        {
            policy.ToTable("SsoPolicies");
            policy.HasKey(entity => entity.TenantId);
            policy.Property(entity => entity.Provider).HasMaxLength(100);
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
        services.TryAddScoped<IEnterpriseUnitOfWork, EnterpriseUnitOfWork>();
        services.TryAddScoped<IDnsTxtResolver, DnsOverHttpsResolver>();
        services.AddHttpClient(DnsOverHttpsResolver.HttpClientName);

        services.RemoveAll<IHomeRealmDirectory>();
        services.AddScoped<IHomeRealmDirectory, EnterpriseHomeRealms>();

        services
            .AddHandler<ClaimDomainHandler>()
            .AddHandler<VerifyDomainHandler>()
            .AddHandler<ListDomainsHandler>()
            .AddHandler<RemoveDomainHandler>()
            .AddHandler<GetSsoPolicyHandler>()
            .AddHandler<SetSsoPolicyHandler>();

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

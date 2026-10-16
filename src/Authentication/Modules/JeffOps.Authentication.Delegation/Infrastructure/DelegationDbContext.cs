using JeffOps.Authentication.Delegation.Application;
using JeffOps.Authentication.Delegation.Domain;
using JeffOps.Authentication.SharedKernel.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace JeffOps.Authentication.Delegation.Infrastructure;

/// <summary>The delegation store (schema <c>delegation</c>). Provider-neutral; SQL Server migrations ship separately.</summary>
public sealed class DelegationDbContext(DbContextOptions<DelegationDbContext> options) : DbContext(options)
{
    public const string Schema = "delegation";

    public DbSet<ImpersonationGrant> ImpersonationGrants => Set<ImpersonationGrant>();

    public DbSet<TenantAccessGrant> TenantAccessGrants => Set<TenantAccessGrant>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        modelBuilder.HasDefaultSchema(Schema);

        modelBuilder.Entity<ImpersonationGrant>(grant =>
        {
            grant.ToTable("ImpersonationGrants");
            ConfigureGrant(grant);
            grant.Property(entity => entity.ActorKind).HasConversion<string>().HasMaxLength(20);
            grant.Property(entity => entity.Reason).HasMaxLength(500);
            grant.HasIndex(entity => new { entity.TargetUserId, entity.Status });
            grant.HasIndex(entity => new { entity.ActorUserId, entity.Status });
        });

        modelBuilder.Entity<TenantAccessGrant>(grant =>
        {
            grant.ToTable("TenantAccessGrants");
            ConfigureGrant(grant);
            grant.HasIndex(entity => new { entity.TargetTenantId, entity.Status });
            grant.HasIndex(entity => new { entity.ActorUserId, entity.TargetTenantId, entity.Status });
        });
    }

    private static void ConfigureGrant<TGrant>(EntityTypeBuilder<TGrant> grant)
        where TGrant : DelegationGrant
    {
        grant.HasKey(entity => entity.Id);
        grant.Property(entity => entity.Id).ValueGeneratedNever();
        grant.Property(entity => entity.Status).HasConversion<string>().HasMaxLength(20).IsConcurrencyToken();
        grant.Property(entity => entity.EndedReason).HasMaxLength(40);
        grant.Ignore(entity => entity.DomainEvents);
        grant.Ignore(entity => entity.IsTerminal);
    }
}

internal sealed class ImpersonationGrantRepository(DelegationDbContext db) : IImpersonationGrantRepository
{
    public Task<ImpersonationGrant?> FindAsync(Guid grantId, CancellationToken cancellationToken) =>
        db.ImpersonationGrants.FirstOrDefaultAsync(grant => grant.Id == grantId, cancellationToken);

    public async Task<IReadOnlyList<ImpersonationGrant>> ListOpenAsync(Guid userId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var candidates = await db.ImpersonationGrants
            .Where(grant => (grant.ActorUserId == userId || grant.TargetUserId == userId)
                && (grant.Status == DelegationGrantStatus.PendingApproval || grant.Status == DelegationGrantStatus.Approved || grant.Status == DelegationGrantStatus.Active))
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return [.. candidates.Where(grant => grant.IsPendingAt(now) || grant.IsLiveAt(now))];
    }

    public void Add(ImpersonationGrant grant) => db.ImpersonationGrants.Add(grant);
}

internal sealed class TenantAccessGrantRepository(DelegationDbContext db) : ITenantAccessGrantRepository
{
    public Task<TenantAccessGrant?> FindAsync(Guid grantId, CancellationToken cancellationToken) =>
        db.TenantAccessGrants.FirstOrDefaultAsync(grant => grant.Id == grantId, cancellationToken);

    public async Task<IReadOnlyList<TenantAccessGrant>> ListOpenAsync(Guid? actorUserId, Guid? tenantId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        var query = db.TenantAccessGrants.Where(grant =>
            grant.Status == DelegationGrantStatus.PendingApproval || grant.Status == DelegationGrantStatus.Approved || grant.Status == DelegationGrantStatus.Active);
        if (actorUserId is { } actor)
        {
            query = query.Where(grant => grant.ActorUserId == actor);
        }

        if (tenantId is { } tenant)
        {
            query = query.Where(grant => grant.TargetTenantId == tenant);
        }

        var candidates = await query.ToListAsync(cancellationToken).ConfigureAwait(false);
        return [.. candidates.Where(grant => grant.IsPendingAt(now) || grant.IsLiveAt(now))];
    }

    public void Add(TenantAccessGrant grant) => db.TenantAccessGrants.Add(grant);
}

internal sealed class DueGrantSource(DelegationDbContext db) : IDueGrantSource
{
    public async Task<IReadOnlyList<DelegationGrant>> ListDueAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        // Open grants are few; the time comparison runs in memory so it works on every provider (SQLite can't compare
        // DateTimeOffset).
        var impersonations = await db.ImpersonationGrants.Where(grant =>
                grant.Status == DelegationGrantStatus.PendingApproval || grant.Status == DelegationGrantStatus.Approved || grant.Status == DelegationGrantStatus.Active)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        var accesses = await db.TenantAccessGrants.Where(grant =>
                grant.Status == DelegationGrantStatus.PendingApproval || grant.Status == DelegationGrantStatus.Approved || grant.Status == DelegationGrantStatus.Active)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
        return [.. impersonations.Cast<DelegationGrant>().Concat(accesses).Where(grant => !grant.IsPendingAt(now) && !grant.IsLiveAt(now))];
    }
}

/// <summary>Saves, then dispatches the saved aggregates' domain events. A concurrency conflict saves nothing and drops them.</summary>
internal sealed class DelegationUnitOfWork(DelegationDbContext db, IDomainEventDispatcher dispatcher) : IDelegationUnitOfWork
{
    public async Task<bool> TrySaveChangesAsync(CancellationToken cancellationToken)
    {
        var aggregates = db.ChangeTracker.Entries<IHasDomainEvents>().Select(entry => entry.Entity).Where(entity => entity.DomainEvents.Count > 0).ToList();
        var events = aggregates.SelectMany(aggregate => aggregate.DomainEvents).ToList();
        foreach (var aggregate in aggregates)
        {
            aggregate.ClearDomainEvents();
        }

        try
        {
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (DbUpdateConcurrencyException)
        {
            return false;
        }

        // Committed: the change is announced, audited and notified even if the caller has gone away meanwhile.
        await dispatcher.DispatchAsync(events, CancellationToken.None).ConfigureAwait(false);
        return true;
    }

    public async Task ReloadAsync(DelegationGrant grant, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grant);
        grant.ClearDomainEvents();
        await db.Entry(grant).ReloadAsync(cancellationToken).ConfigureAwait(false);
    }
}

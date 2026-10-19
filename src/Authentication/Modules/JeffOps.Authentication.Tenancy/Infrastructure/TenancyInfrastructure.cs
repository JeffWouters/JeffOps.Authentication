using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Application.Federation;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.SharedKernel.DependencyInjection;
using JeffOps.Authentication.SharedKernel.Domain;
using JeffOps.Authentication.Tenancy.Application;
using JeffOps.Authentication.Tenancy.Application.Features.Directories;
using JeffOps.Authentication.Tenancy.Application.Features.Invitations;
using JeffOps.Authentication.Tenancy.Application.Features.Members;
using JeffOps.Authentication.Tenancy.Application.Features.Signup;
using JeffOps.Authentication.Tenancy.Application.Features.Tenants;
using JeffOps.Authentication.Tenancy.Domain;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Tenancy.Infrastructure;

/// <summary>The tenancy store (schema <c>tenancy</c>). Provider-neutral; SQL Server migrations ship separately.</summary>
public sealed class TenancyDbContext(DbContextOptions<TenancyDbContext> options) : DbContext(options)
{
    public const string Schema = "tenancy";

    public DbSet<Tenant> Tenants => Set<Tenant>();

    public DbSet<Membership> Memberships => Set<Membership>();

    public DbSet<DirectoryLink> DirectoryLinks => Set<DirectoryLink>();

    public DbSet<Invitation> Invitations => Set<Invitation>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);
        modelBuilder.HasDefaultSchema(Schema);

        modelBuilder.Entity<Tenant>(tenant =>
        {
            tenant.ToTable("Tenants");
            tenant.HasKey(entity => entity.Id);
            tenant.Property(entity => entity.Id).ValueGeneratedNever();
            tenant.Property(entity => entity.Name).HasMaxLength(Tenant.MaxNameLength).IsRequired();
            tenant.Property(entity => entity.Status).HasConversion<string>().HasMaxLength(20);
            tenant.HasIndex(entity => entity.CreatedAt);
            // One platform tenant, enforced by the store too.
            tenant.HasIndex(entity => entity.IsPlatform).IsUnique().HasFilter("[IsPlatform] = 1").HasDatabaseName("IX_Tenants_Platform");
            tenant.Ignore(entity => entity.AcceptsSessions);
            tenant.Ignore(entity => entity.DomainEvents);
        });

        modelBuilder.Entity<Membership>(membership =>
        {
            membership.ToTable("Memberships");
            membership.HasKey(entity => new { entity.TenantId, entity.AccountId });
            membership.Property(entity => entity.Role).HasConversion<string>().HasMaxLength(20);
            membership.Property(entity => entity.Source).HasConversion<string>().HasMaxLength(20);
            membership.HasIndex(entity => entity.AccountId);
            membership.Ignore(entity => entity.IsAdmin);
        });

        modelBuilder.Entity<DirectoryLink>(link =>
        {
            link.ToTable("DirectoryLinks");
            // A directory belongs to one tenant at most.
            link.HasKey(entity => new { entity.Kind, entity.DirectoryId });
            link.Property(entity => entity.Kind).HasMaxLength(20);
            link.Property(entity => entity.DirectoryId).HasMaxLength(100);
            link.HasIndex(entity => entity.TenantId);
        });

        modelBuilder.Entity<Invitation>(invitation =>
        {
            invitation.ToTable("Invitations");
            invitation.HasKey(entity => entity.Id);
            invitation.Property(entity => entity.Id).ValueGeneratedNever();
            invitation.Property(entity => entity.Email).HasMaxLength(Invitation.MaxEmailLength);
            invitation.Property(entity => entity.Role).HasConversion<string>().HasMaxLength(20);
            invitation.Property(entity => entity.TokenHash).HasMaxLength(64).IsRequired();
            invitation.HasIndex(entity => entity.TokenHash).IsUnique();
            invitation.HasIndex(entity => entity.TenantId);
            invitation.Ignore(entity => entity.DomainEvents);
        });

        // SQLite can't compare DateTimeOffset values (invitation expiry): there, store them as order-preserving integers.
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

internal sealed class TenantRepository(TenancyDbContext db) : ITenantRepository
{
    public Task<Tenant?> FindAsync(Guid tenantId, CancellationToken cancellationToken) =>
        db.Tenants.FirstOrDefaultAsync(tenant => tenant.Id == tenantId, cancellationToken);

    public Task<Tenant?> FindPlatformAsync(CancellationToken cancellationToken) =>
        db.Tenants.FirstOrDefaultAsync(tenant => tenant.IsPlatform, cancellationToken);

    public async Task<IReadOnlyList<Tenant>> ListAsync(string? nameContains, int skip, int take, CancellationToken cancellationToken)
    {
        var query = db.Tenants.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(nameContains))
        {
            var pattern = "%" + nameContains.Trim().Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal)
                .Replace("_", "\\_", StringComparison.Ordinal).Replace("[", "\\[", StringComparison.Ordinal) + "%";
            query = query.Where(tenant => EF.Functions.Like(tenant.Name, pattern, "\\"));
        }

        return await query.OrderByDescending(tenant => tenant.CreatedAt).ThenBy(tenant => tenant.Id).Skip(skip).Take(take)
            .ToListAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyDictionary<Guid, Tenant>> FindManyAsync(IReadOnlyCollection<Guid> tenantIds, CancellationToken cancellationToken) =>
        tenantIds.Count == 0
            ? new Dictionary<Guid, Tenant>()
            : await db.Tenants.AsNoTracking().Where(tenant => tenantIds.Contains(tenant.Id)).ToDictionaryAsync(tenant => tenant.Id, cancellationToken).ConfigureAwait(false);

    public void Add(Tenant tenant) => db.Tenants.Add(tenant);
}

internal sealed class MembershipRepository(TenancyDbContext db) : IMembershipRepository
{
    public Task<Membership?> FindAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken) =>
        db.Memberships.FirstOrDefaultAsync(membership => membership.TenantId == tenantId && membership.AccountId == accountId, cancellationToken);

    public async Task<IReadOnlyList<Membership>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        await db.Memberships.AsNoTracking().Where(membership => membership.TenantId == tenantId)
            .OrderBy(membership => membership.CreatedAt).ThenBy(membership => membership.AccountId)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public async Task<IReadOnlyList<Membership>> ListForAccountAsync(Guid accountId, CancellationToken cancellationToken) =>
        await db.Memberships.AsNoTracking().Where(membership => membership.AccountId == accountId)
            .OrderBy(membership => membership.CreatedAt).ThenBy(membership => membership.TenantId)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

    public Task<int> CountAdminsAsync(Guid tenantId, CancellationToken cancellationToken) =>
        db.Memberships.CountAsync(membership => membership.TenantId == tenantId && membership.Role == MembershipRole.Admin, cancellationToken);

    public void Add(Membership membership) => db.Memberships.Add(membership);

    public void Remove(Membership membership) => db.Memberships.Remove(membership);
}

internal sealed class DirectoryLinkRepository(TenancyDbContext db) : IDirectoryLinkRepository
{
    public Task<DirectoryLink?> FindAsync(string kind, string directoryId, CancellationToken cancellationToken) =>
        db.DirectoryLinks.FirstOrDefaultAsync(link => link.Kind == kind && link.DirectoryId == directoryId, cancellationToken);

    public async Task<IReadOnlyList<DirectoryLink>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        await db.DirectoryLinks.AsNoTracking().Where(link => link.TenantId == tenantId).OrderBy(link => link.CreatedAt).ToListAsync(cancellationToken).ConfigureAwait(false);

    public void Add(DirectoryLink link) => db.DirectoryLinks.Add(link);

    public void Remove(DirectoryLink link) => db.DirectoryLinks.Remove(link);
}

internal sealed class InvitationRepository(TenancyDbContext db) : IInvitationRepository
{
    public Task<Invitation?> FindAsync(Guid invitationId, CancellationToken cancellationToken) =>
        db.Invitations.FirstOrDefaultAsync(invitation => invitation.Id == invitationId, cancellationToken);

    public Task<Invitation?> FindByTokenHashAsync(string tokenHash, CancellationToken cancellationToken) =>
        db.Invitations.FirstOrDefaultAsync(invitation => invitation.TokenHash == tokenHash, cancellationToken);

    public async Task<IReadOnlyList<Invitation>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        await db.Invitations.AsNoTracking().Where(invitation => invitation.TenantId == tenantId)
            .OrderByDescending(invitation => invitation.CreatedAt).Take(500).ToListAsync(cancellationToken).ConfigureAwait(false);

    public Task<int> CountOpenAsync(Guid tenantId, DateTimeOffset now, CancellationToken cancellationToken) =>
        db.Invitations.CountAsync(invitation => invitation.TenantId == tenantId && invitation.AcceptedAt == null && invitation.RevokedAt == null
            && invitation.ExpiresAt > now, cancellationToken);

    public void Add(Invitation invitation) => db.Invitations.Add(invitation);
}

internal sealed class TenancyUnitOfWork(TenancyDbContext db, IDomainEventDispatcher dispatcher) : ITenancyUnitOfWork
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

    public async Task<bool> TrySaveUniqueAsync(CancellationToken cancellationToken)
    {
        try
        {
            await SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (DbUpdateException)
        {
            db.ChangeTracker.Clear();
            return false;
        }
    }
}

/// <summary>
/// The token server's view of tenancy (<see cref="ITenantDirectory"/>): memberships from the store, oldest first, so a
/// session lands in the account's first tenant unless the client passes <c>tenant_hint</c>. Removing a membership or closing a
/// tenant takes effect at the next refresh.
/// </summary>
internal sealed class StoreTenantDirectory(IMembershipRepository memberships, ITenantRepository tenants) : ITenantDirectory
{
    public async Task<IReadOnlyList<TenantMembership>> GetMembershipsAsync(Guid accountId, CancellationToken cancellationToken)
    {
        var mine = await memberships.ListForAccountAsync(accountId, cancellationToken).ConfigureAwait(false);
        var byId = await tenants.FindManyAsync([.. mine.Select(membership => membership.TenantId)], cancellationToken).ConfigureAwait(false);
        return [.. mine
            .Where(membership => byId.TryGetValue(membership.TenantId, out var tenant) && tenant.Status != TenantStatus.Deleted)
            .Select(membership => new TenantMembership(membership.TenantId, null, null, AccessLevel.Tenant))];
    }

    public async Task<TenantInfo?> FindTenantAsync(Guid tenantId, CancellationToken cancellationToken) =>
        await tenants.FindAsync(tenantId, cancellationToken).ConfigureAwait(false) is { } tenant
            ? new TenantInfo(tenant.Id, null, tenant.AcceptsSessions)
            : null;
}

/// <summary>
/// Joins accounts to tenants as they sign in: platform operators named in configuration, people from a linked Entra
/// directory, and people who signed in through a tenant's own identity provider. Runs before the session starts, so the new
/// membership is in the first token.
/// </summary>
internal sealed partial class MembershipSignInObserver(
    MembershipJoin join,
    IDirectoryLinkRepository links,
    ITenantRepository tenants,
    ITenantProviderDirectory tenantProviders,
    IOptions<TenancyOptions> options,
    ILogger<MembershipSignInObserver> logger) : IExternalSignInObserver
{
    public async Task OnSignedInAsync(Guid accountId, ExternalIdentity identity, bool isNewAccount, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);

        if (PlatformBootstrap.IsConfiguredOperator(options.Value, identity.Login)
            && await tenants.FindPlatformAsync(cancellationToken).ConfigureAwait(false) is { } platform)
        {
            await join.EnsureAsync(platform.Id, accountId, MembershipRole.Admin, MembershipSource.Operator, cancellationToken).ConfigureAwait(false);
        }

        if (identity.DirectoryId is { } directory && Guid.TryParse(directory, out var entraDirectory)
            && identity.Login.Issuer.Equals(DirectoryLink.EntraIssuer(entraDirectory), StringComparison.OrdinalIgnoreCase)
            && await links.FindAsync(DirectoryLink.EntraKind, DirectoryLink.NormalizeEntra(entraDirectory), cancellationToken).ConfigureAwait(false) is { } link
            && await join.EnsureAsync(link.TenantId, accountId, MembershipRole.Member, MembershipSource.Directory, cancellationToken).ConfigureAwait(false))
        {
            LogJoined(logger, accountId, link.TenantId, "directory");
        }

        var ssoTenant = TenantProviderNames.IsSaml(identity.Provider)
            ? (await tenantProviders.FindSamlAsync(identity.Provider, cancellationToken).ConfigureAwait(false))?.TenantId
            : TenantProviderNames.IsOidc(identity.Provider)
                ? (await tenantProviders.FindOidcAsync(identity.Provider, cancellationToken).ConfigureAwait(false))?.TenantId
                : null;
        if (ssoTenant is { } tenantId
            && await join.EnsureAsync(tenantId, accountId, MembershipRole.Member, MembershipSource.Sso, cancellationToken).ConfigureAwait(false))
        {
            LogJoined(logger, accountId, tenantId, "sso");
        }
    }

    [LoggerMessage(EventId = 9301, Level = LogLevel.Information, Message = "Account {AccountId} is a member of tenant {TenantId} ({Source}).")]
    private static partial void LogJoined(ILogger logger, Guid accountId, Guid tenantId, string source);
}

/// <summary>SCIM provisioning adds members and removes the memberships it created (not ones from invitations or operators).</summary>
internal sealed class ScimMembershipProvisioner(MembershipJoin join, IMembershipRepository memberships, ITenancyUnitOfWork unitOfWork) : ITenantMembershipProvisioner
{
    public Task AddMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken) =>
        join.EnsureAsync(tenantId, accountId, MembershipRole.Member, MembershipSource.Scim, cancellationToken);

    public async Task RemoveMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken)
    {
        if (await memberships.FindAsync(tenantId, accountId, cancellationToken).ConfigureAwait(false) is { Source: MembershipSource.Scim } membership)
        {
            memberships.Remove(membership);
            await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }
}

/// <summary>Creates the platform tenant from configuration once, and makes the configured operators its administrators.</summary>
internal static partial class PlatformBootstrap
{
    public static bool IsConfiguredOperator(TenancyOptions options, ExternalLoginKey login) =>
        options.Platform.Operators.Any(candidate =>
            string.Equals(candidate.Issuer, login.Issuer, StringComparison.Ordinal) && string.Equals(candidate.Subject, login.Subject, StringComparison.Ordinal));

    public static async Task RunAsync(IServiceProvider services, CancellationToken cancellationToken)
    {
        var settings = services.GetRequiredService<IOptions<TenancyOptions>>().Value.Platform;
        if (string.IsNullOrWhiteSpace(settings.Name))
        {
            return;
        }

        var tenants = services.GetRequiredService<ITenantRepository>();
        var links = services.GetRequiredService<IDirectoryLinkRepository>();
        var unitOfWork = services.GetRequiredService<ITenancyUnitOfWork>();
        var time = services.GetRequiredService<TimeProvider>();
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(PlatformBootstrap));

        if (await tenants.FindPlatformAsync(cancellationToken).ConfigureAwait(false) is null)
        {
            var platform = Tenant.CreatePlatform(settings.Name, time.GetUtcNow());
            tenants.Add(platform);
            if (settings.EntraDirectoryId is { } directory && directory != Guid.Empty
                && await links.FindAsync(DirectoryLink.EntraKind, DirectoryLink.NormalizeEntra(directory), cancellationToken).ConfigureAwait(false) is null)
            {
                links.Add(DirectoryLink.Entra(platform.Id, directory, linkedBy: null, time.GetUtcNow()));
            }

            // Another instance starting at the same time may have created it: the unique index keeps one.
            if (await unitOfWork.TrySaveUniqueAsync(cancellationToken).ConfigureAwait(false))
            {
                LogCreated(logger, platform.Id, platform.Name);
            }
        }

        if (await tenants.FindPlatformAsync(cancellationToken).ConfigureAwait(false) is not { } current)
        {
            return;
        }

        var accounts = services.GetRequiredService<IAccountRepository>();
        var join = services.GetRequiredService<MembershipJoin>();
        foreach (var candidate in settings.Operators.Where(candidate => !string.IsNullOrWhiteSpace(candidate.Issuer) && !string.IsNullOrWhiteSpace(candidate.Subject)))
        {
            // Not signed in yet: they become administrator at their first sign-in (MembershipSignInObserver).
            if (await accounts.FindByExternalLoginAsync(new ExternalLoginKey(candidate.Issuer!, candidate.Subject!), cancellationToken).ConfigureAwait(false) is { } account)
            {
                await join.EnsureAsync(current.Id, account.Id, MembershipRole.Admin, MembershipSource.Operator, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    [LoggerMessage(EventId = 9302, Level = LogLevel.Warning, Message = "Created the platform tenant {TenantId} ({Name}).")]
    private static partial void LogCreated(ILogger logger, Guid tenantId, string name);
}

/// <summary>A tenant administrator of the caller's session tenant, in their own session.</summary>
internal sealed class TenantAdministratorRequirement : IAuthorizationRequirement;

/// <summary>An administrator of the platform tenant, in their own session.</summary>
internal sealed class PlatformOperatorRequirement : IAuthorizationRequirement;

internal sealed class TenancyAuthorizationHandler(IMembershipRepository memberships, ITenantRepository tenants, IServiceProvider services)
    : IAuthorizationHandler
{
    public async Task HandleAsync(AuthorizationHandlerContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var names = services.GetService<ClaimNames>() ?? ClaimNames.Default;
        if (!AccessContextReader.IsOwnSession(context.User, names) || AccessContextReader.Read(context.User, names) is not { UserId: { } accountId } access)
        {
            return;
        }

        foreach (var requirement in context.PendingRequirements.ToList())
        {
            var tenantId = requirement switch
            {
                TenantAdministratorRequirement => access.TenantId,
                PlatformOperatorRequirement => (await tenants.FindPlatformAsync(CancellationToken.None).ConfigureAwait(false))?.Id,
                _ => null,
            };
            if (tenantId is { } id
                && await tenants.FindAsync(id, CancellationToken.None).ConfigureAwait(false) is { AcceptsSessions: true }
                && await memberships.FindAsync(id, accountId, CancellationToken.None).ConfigureAwait(false) is { IsAdmin: true })
            {
                context.Succeed(requirement);
            }
        }
    }
}

/// <summary>Returned by <see cref="TenancyServiceCollectionExtensions.AddTenancy"/>.</summary>
public sealed record TenancyBuilder(IServiceCollection Services)
{
    /// <summary>
    /// Configures the tenancy store's database provider. Contexts are pooled: <paramref name="configure"/> runs once, with the
    /// root service provider, so it must not resolve scoped services.
    /// </summary>
    public TenancyBuilder UseDatabase(Action<IServiceProvider, DbContextOptionsBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        Services.AddDbContextPool<TenancyDbContext>((provider, options) =>
        {
            options.ConfigureWarnings(warnings => warnings.Log((RelationalEventId.CommandExecuted, LogLevel.Debug)));
            configure(provider, options);
        });
        return this;
    }
}

/// <summary>Prepares the tenancy database, for example by applying migrations.</summary>
public interface ITenancyDatabaseInitializer
{
    Task InitializeAsync(CancellationToken cancellationToken);
}

public static class TenancyServiceCollectionExtensions
{
    /// <summary>
    /// Adds tenancy (docs/DESIGN.md §8.6): tenants shared by every product, memberships (linked Entra directories, invitations,
    /// a tenant's own SSO, SCIM), tenant administrators and platform operators. Replaces the token server's tenant directory and
    /// the Enterprise module's membership provisioning, and defines the authorization policies they ask for. Map the endpoints
    /// with <c>MapJeffOpsTenancy</c>.
    /// </summary>
    public static TenancyBuilder AddTenancy(this AuthenticationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.Services.AddJeffOpsTenancy(builder.Configuration);
    }

    /// <summary>The registrations behind <see cref="AddTenancy"/>.</summary>
    public static TenancyBuilder AddJeffOpsTenancy(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<TenancyOptions>().Bind(configuration.GetSection(TenancyOptions.SectionName));
        services.TryAddScoped<ITenantRepository, TenantRepository>();
        services.TryAddScoped<IMembershipRepository, MembershipRepository>();
        services.TryAddScoped<IDirectoryLinkRepository, DirectoryLinkRepository>();
        services.TryAddScoped<IInvitationRepository, InvitationRepository>();
        services.TryAddScoped<ITenancyUnitOfWork, TenancyUnitOfWork>();
        services.TryAddScoped<MembershipJoin>();

        // Tenancy is the source of truth for memberships, whichever module was added first.
        services.RemoveAll<ITenantDirectory>();
        services.AddScoped<ITenantDirectory, StoreTenantDirectory>();
        services.RemoveAll<ITenantMembershipProvisioner>();
        services.AddScoped<ITenantMembershipProvisioner, ScimMembershipProvisioner>();
        services.AddScoped<IExternalSignInObserver, MembershipSignInObserver>();
        services.TryAddScoped<ITenantProviderDirectory, NoTenantProviders>();

        services.AddScoped<IAuthorizationHandler, TenancyAuthorizationHandler>();
        services.AddOptions<AuthorizationOptions>().Configure<IOptions<TenancyOptions>>((authorization, tenancy) =>
        {
            var settings = tenancy.Value;
            if (!settings.DefinePolicies)
            {
                return;
            }

            AuthorizationPolicy Policy(IAuthorizationRequirement requirement) => new AuthorizationPolicyBuilder().RequireAuthenticatedUser().AddRequirements(requirement).Build();
            authorization.AddPolicy(settings.ManagePolicy, Policy(new TenantAdministratorRequirement()));
            authorization.AddPolicy(settings.ScimTokenPolicy, Policy(new TenantAdministratorRequirement()));
            authorization.AddPolicy(settings.OperatorPolicy, Policy(new PlatformOperatorRequirement()));
            authorization.AddPolicy(settings.AccountAdministrationPolicy, Policy(new PlatformOperatorRequirement()));
        });

        services
            .AddHandler<CreateTenantHandler>()
            .AddHandler<ListTenantsHandler>()
            .AddHandler<GetTenantHandler>()
            .AddHandler<UpdateTenantHandler>()
            .AddHandler<ListMyTenantsHandler>()
            .AddHandler<ListMembersHandler>()
            .AddHandler<AddMemberHandler>()
            .AddHandler<SetMemberRoleHandler>()
            .AddHandler<RemoveMemberHandler>()
            .AddHandler<ListDirectoriesHandler>()
            .AddHandler<LinkDirectoryHandler>()
            .AddHandler<UnlinkDirectoryHandler>()
            .AddHandler<CreateInvitationHandler>()
            .AddHandler<ListInvitationsHandler>()
            .AddHandler<RevokeInvitationHandler>()
            .AddHandler<PreviewInvitationHandler>()
            .AddHandler<AcceptInvitationHandler>()
            .AddHandler<SignupTenantHandler>();

        services.AddHostedService<TenancyStartup>();
        return new TenancyBuilder(services);
    }
}

/// <summary>Prepares the database, then creates the platform tenant and its configured operators.</summary>
internal sealed class TenancyStartup(IServiceProvider services) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = services.CreateAsyncScope();
        foreach (var initializer in scope.ServiceProvider.GetServices<ITenancyDatabaseInitializer>())
        {
            await initializer.InitializeAsync(cancellationToken).ConfigureAwait(false);
        }

        await PlatformBootstrap.RunAsync(scope.ServiceProvider, cancellationToken).ConfigureAwait(false);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

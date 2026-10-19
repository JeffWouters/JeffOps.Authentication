using JeffOps.Authentication.Tenancy.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Tenancy.SqlServer;

/// <summary>Registers SQL Server as the tenancy module's database.</summary>
public static class TenancySqlServerExtensions
{
    /// <summary>
    /// Stores tenants, memberships, linked directories and invitations in SQL Server (schema <c>tenancy</c>), using the
    /// connection string <paramref name="connectionStringName"/> — by default the token server's own database. With
    /// <paramref name="migrateOnStartup"/>, pending migrations are applied at startup.
    /// </summary>
    public static TenancyBuilder AddSqlServerPersistence(this TenancyBuilder builder, string connectionStringName = "authentication", bool migrateOnStartup = false)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionStringName);

        builder.UseDatabase((provider, options) =>
        {
            var connectionString = provider.GetRequiredService<IConfiguration>().GetConnectionString(connectionStringName)
                ?? throw new InvalidOperationException($"The connection string '{connectionStringName}' is not configured.");
            options.UseSqlServer(connectionString, Configure);
        });

        if (migrateOnStartup)
        {
            builder.Services.AddScoped<ITenancyDatabaseInitializer, MigrateDatabase>();
        }

        return builder;
    }

    internal static void Configure(Microsoft.EntityFrameworkCore.Infrastructure.SqlServerDbContextOptionsBuilder sql) =>
        sql.MigrationsAssembly(typeof(TenancySqlServerExtensions).Assembly.GetName().Name)
            .MigrationsHistoryTable("__EFMigrationsHistory", TenancyDbContext.Schema)
            .EnableRetryOnFailure();

    private sealed class MigrateDatabase(TenancyDbContext db) : ITenancyDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.MigrateAsync(cancellationToken);
    }
}

/// <summary>Used by <c>dotnet ef migrations</c> only.</summary>
internal sealed class DesignTimeContextFactory : IDesignTimeDbContextFactory<TenancyDbContext>
{
    public TenancyDbContext CreateDbContext(string[] args)
    {
        // SqlClient's native networking isn't shipped here (docs/DESIGN.md §6.5, D24): the tools use managed networking.
        AppContext.SetSwitch("Switch.Microsoft.Data.SqlClient.UseManagedNetworkingOnWindows", true);
        var options = new DbContextOptionsBuilder<TenancyDbContext>()
            .UseSqlServer("Server=(localdb)\\design-time;Database=JeffOpsAuthentication", TenancySqlServerExtensions.Configure)
            .Options;
        return new TenancyDbContext(options);
    }
}

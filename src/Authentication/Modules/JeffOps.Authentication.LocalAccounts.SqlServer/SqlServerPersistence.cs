using JeffOps.Authentication.LocalAccounts.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.LocalAccounts.SqlServer;

/// <summary>Registers SQL Server as the local accounts module's database.</summary>
public static class LocalAccountsSqlServerExtensions
{
    /// <summary>
    /// Stores local credentials in SQL Server (schema <c>local</c>), using the connection string
    /// <paramref name="connectionStringName"/> — by default the token server's own database. With
    /// <paramref name="migrateOnStartup"/>, pending migrations are applied at startup.
    /// </summary>
    public static LocalAccountsBuilder AddSqlServerPersistence(this LocalAccountsBuilder builder, string connectionStringName = "authentication", bool migrateOnStartup = false)
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
            builder.Services.AddScoped<ILocalAccountsDatabaseInitializer, MigrateDatabase>();
        }

        return builder;
    }

    internal static void Configure(Microsoft.EntityFrameworkCore.Infrastructure.SqlServerDbContextOptionsBuilder sql) =>
        sql.MigrationsAssembly(typeof(LocalAccountsSqlServerExtensions).Assembly.GetName().Name)
            .MigrationsHistoryTable("__EFMigrationsHistory", LocalAccountsDbContext.Schema)
            .EnableRetryOnFailure();

    private sealed class MigrateDatabase(LocalAccountsDbContext db) : ILocalAccountsDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.MigrateAsync(cancellationToken);
    }
}

/// <summary>Used by <c>dotnet ef migrations</c> only.</summary>
internal sealed class DesignTimeContextFactory : IDesignTimeDbContextFactory<LocalAccountsDbContext>
{
    public LocalAccountsDbContext CreateDbContext(string[] args)
    {
        // SqlClient's native networking isn't shipped here (docs/DESIGN.md §6.5, D24): the tools use managed networking.
        AppContext.SetSwitch("Switch.Microsoft.Data.SqlClient.UseManagedNetworkingOnWindows", true);
        var options = new DbContextOptionsBuilder<LocalAccountsDbContext>()
            .UseSqlServer("Server=(localdb)\\design-time;Database=JeffOpsAuthentication", LocalAccountsSqlServerExtensions.Configure)
            .Options;
        return new LocalAccountsDbContext(options);
    }
}

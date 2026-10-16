using JeffOps.Authentication.Delegation.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Delegation.SqlServer;

/// <summary>Registers SQL Server as the delegation module's database.</summary>
public static class DelegationSqlServerExtensions
{
    /// <summary>
    /// Stores delegation grants in SQL Server (schema <c>delegation</c>), using the connection string
    /// <paramref name="connectionStringName"/> — by default the token server's own database. With
    /// <paramref name="migrateOnStartup"/>, pending migrations are applied at startup.
    /// </summary>
    public static DelegationBuilder AddSqlServerPersistence(this DelegationBuilder builder, string connectionStringName = "authentication", bool migrateOnStartup = false)
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
            builder.Services.AddScoped<IDelegationDatabaseInitializer, MigrateDatabase>();
        }

        return builder;
    }

    internal static void Configure(Microsoft.EntityFrameworkCore.Infrastructure.SqlServerDbContextOptionsBuilder sql) =>
        sql.MigrationsAssembly(typeof(DelegationSqlServerExtensions).Assembly.GetName().Name)
            .MigrationsHistoryTable("__EFMigrationsHistory", DelegationDbContext.Schema)
            .EnableRetryOnFailure();

    private sealed class MigrateDatabase(DelegationDbContext db) : IDelegationDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.MigrateAsync(cancellationToken);
    }
}

/// <summary>Used by <c>dotnet ef migrations</c> only.</summary>
internal sealed class DesignTimeContextFactory : IDesignTimeDbContextFactory<DelegationDbContext>
{
    public DelegationDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<DelegationDbContext>()
            .UseSqlServer("Server=(localdb)\\design-time;Database=JeffOpsAuthentication", DelegationSqlServerExtensions.Configure)
            .Options;
        return new DelegationDbContext(options);
    }
}

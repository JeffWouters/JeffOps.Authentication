using JeffOps.Authentication.Enterprise.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Enterprise.SqlServer;

public static class EnterpriseSqlServerExtensions
{
    /// <summary>
    /// Stores verified domains, SSO policies and SCIM data in SQL Server (schema <c>enterprise</c>), using the connection string
    /// <paramref name="connectionStringName"/> — by default the token server's own database. With
    /// <paramref name="migrateOnStartup"/>, pending migrations are applied at startup.
    /// </summary>
    public static EnterpriseBuilder AddSqlServerPersistence(this EnterpriseBuilder builder, string connectionStringName = "authentication", bool migrateOnStartup = false)
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
            builder.Services.AddScoped<IEnterpriseDatabaseInitializer, MigrateDatabase>();
        }

        return builder;
    }

    internal static void Configure(Microsoft.EntityFrameworkCore.Infrastructure.SqlServerDbContextOptionsBuilder sql) =>
        sql.MigrationsAssembly(typeof(EnterpriseSqlServerExtensions).Assembly.GetName().Name)
            .MigrationsHistoryTable("__EFMigrationsHistory", EnterpriseDbContext.Schema)
            .EnableRetryOnFailure();

    private sealed class MigrateDatabase(EnterpriseDbContext db) : IEnterpriseDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.MigrateAsync(cancellationToken);
    }
}

/// <summary>Used by <c>dotnet ef migrations</c> only.</summary>
internal sealed class DesignTimeContextFactory : IDesignTimeDbContextFactory<EnterpriseDbContext>
{
    public EnterpriseDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<EnterpriseDbContext>()
            .UseSqlServer("Server=(localdb)\\design-time;Database=JeffOpsAuthentication", EnterpriseSqlServerExtensions.Configure)
            .Options;
        return new EnterpriseDbContext(options);
    }
}

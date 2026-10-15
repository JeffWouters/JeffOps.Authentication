using JeffOps.Authorization.Infrastructure.DependencyInjection;
using JeffOps.Authorization.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authorization.Persistence.SqlServer;

public static class SqlServerPersistenceExtensions
{
    /// <summary>
    /// Stores authorization management data in SQL Server, using the connection string <paramref name="connectionStringName"/>.
    /// With <paramref name="migrateOnStartup"/>, pending migrations are applied before seeding; otherwise apply them in your
    /// deployment pipeline.
    /// </summary>
    public static AuthorizationManagementBuilder AddSqlServerPersistence(this AuthorizationManagementBuilder builder, string connectionStringName = "authorization", bool migrateOnStartup = false)
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
            builder.Services.AddScoped<IAuthorizationDatabaseInitializer, MigrateDatabase>();
        }

        return builder;
    }

    internal static void Configure(Microsoft.EntityFrameworkCore.Infrastructure.SqlServerDbContextOptionsBuilder sql) =>
        sql.MigrationsAssembly(typeof(SqlServerPersistenceExtensions).Assembly.GetName().Name)
            .MigrationsHistoryTable("__EFMigrationsHistory", AuthorizationDbContext.Schema)
            .EnableRetryOnFailure();

    private sealed class MigrateDatabase(AuthorizationDbContext db) : IAuthorizationDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.MigrateAsync(cancellationToken);
    }
}

/// <summary>Used by <c>dotnet ef migrations</c> only.</summary>
internal sealed class DesignTimeContextFactory : IDesignTimeDbContextFactory<AuthorizationDbContext>
{
    public AuthorizationDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<AuthorizationDbContext>()
            .UseSqlServer("Server=(localdb)\\design-time;Database=JeffOpsAuthorization", SqlServerPersistenceExtensions.Configure)
            .Options;
        return new AuthorizationDbContext(options);
    }
}

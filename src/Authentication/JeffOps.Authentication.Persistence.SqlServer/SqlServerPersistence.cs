using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Infrastructure.DependencyInjection;
using JeffOps.Authentication.Infrastructure.Persistence;
using JeffOps.Authentication.Infrastructure.Server;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Persistence.SqlServer;

/// <summary>Registers SQL Server as the token server's database.</summary>
public static class SqlServerPersistenceExtensions
{
    /// <summary>
    /// Stores the token server's data in SQL Server, using the connection string <paramref name="connectionStringName"/>
    /// (for example from Aspire). With <paramref name="migrateOnStartup"/>, pending migrations are applied before clients
    /// are seeded; otherwise apply them in your deployment pipeline.
    /// </summary>
    public static AuthenticationBuilder AddSqlServerPersistence(this AuthenticationBuilder builder, string connectionStringName = "authentication", bool migrateOnStartup = false)
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
            builder.Services.AddScoped<IAuthenticationDatabaseInitializer, MigrateDatabase>();
        }

        return builder;
    }

    internal static void Configure(Microsoft.EntityFrameworkCore.Infrastructure.SqlServerDbContextOptionsBuilder sql) =>
        sql.MigrationsAssembly(typeof(SqlServerPersistenceExtensions).Assembly.GetName().Name)
            .MigrationsHistoryTable("__EFMigrationsHistory", AuthenticationDbContext.Schema)
            .EnableRetryOnFailure();

    private sealed class MigrateDatabase(AuthenticationDbContext db) : IAuthenticationDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.MigrateAsync(cancellationToken);
    }
}

/// <summary>Used by <c>dotnet ef migrations</c> only.</summary>
internal sealed class DesignTimeContextFactory : IDesignTimeDbContextFactory<AuthenticationDbContext>
{
    public AuthenticationDbContext CreateDbContext(string[] args)
    {
        var options = new DbContextOptionsBuilder<AuthenticationDbContext>()
            .UseSqlServer("Server=(localdb)\\design-time;Database=JeffOpsAuthentication", SqlServerPersistenceExtensions.Configure)
            .UseOpenIddict()
            .Options;
        return new AuthenticationDbContext(options);
    }
}

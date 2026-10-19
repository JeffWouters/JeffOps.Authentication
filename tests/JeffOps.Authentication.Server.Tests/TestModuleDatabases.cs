using JeffOps.Authentication.Delegation.Infrastructure;
using JeffOps.Authentication.Delegation.SqlServer;
using JeffOps.Authentication.Enterprise.Infrastructure;
using JeffOps.Authentication.Enterprise.SqlServer;
using JeffOps.Authentication.LocalAccounts.Infrastructure;
using JeffOps.Authentication.LocalAccounts.SqlServer;
using JeffOps.Authentication.Tenancy.Infrastructure;
using JeffOps.Authentication.Tenancy.SqlServer;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>
/// Gives a module the test database (<see cref="TestDatabase"/>): its own SQLite file, created from the model; or, on SQL
/// Server, the token server's database with the module's migrations applied at startup, as a host would run it.
/// Initializers a test registers afterwards (seed data) run after the schema exists.
/// </summary>
internal static class TestModuleDatabases
{
    public static DelegationBuilder UseTestDatabase(this DelegationBuilder builder, string sqliteFile)
    {
        if (TestDatabase.SqlServer)
        {
            return builder.AddSqlServerPersistence(migrateOnStartup: true);
        }

        builder.Services.AddScoped<IDelegationDatabaseInitializer, CreateDelegation>();
        return builder.UseDatabase((_, options) => options.UseSqlite(sqliteFile));
    }

    public static EnterpriseBuilder UseTestDatabase(this EnterpriseBuilder builder, string sqliteFile)
    {
        if (TestDatabase.SqlServer)
        {
            return builder.AddSqlServerPersistence(migrateOnStartup: true);
        }

        builder.Services.AddScoped<IEnterpriseDatabaseInitializer, CreateEnterprise>();
        return builder.UseDatabase((_, options) => options.UseSqlite(sqliteFile));
    }

    public static LocalAccountsBuilder UseTestDatabase(this LocalAccountsBuilder builder, string sqliteFile)
    {
        if (TestDatabase.SqlServer)
        {
            return builder.AddSqlServerPersistence(migrateOnStartup: true);
        }

        builder.Services.AddScoped<ILocalAccountsDatabaseInitializer, CreateLocalAccounts>();
        return builder.UseDatabase((_, options) => options.UseSqlite(sqliteFile));
    }

    public static TenancyBuilder UseTestDatabase(this TenancyBuilder builder, string sqliteFile)
    {
        if (TestDatabase.SqlServer)
        {
            return builder.AddSqlServerPersistence(migrateOnStartup: true);
        }

        builder.Services.AddScoped<ITenancyDatabaseInitializer, CreateTenancy>();
        return builder.UseDatabase((_, options) => options.UseSqlite(sqliteFile));
    }

    private sealed class CreateTenancy(TenancyDbContext db) : ITenancyDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.EnsureCreatedAsync(cancellationToken);
    }

    private sealed class CreateDelegation(DelegationDbContext db) : IDelegationDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.EnsureCreatedAsync(cancellationToken);
    }

    private sealed class CreateEnterprise(EnterpriseDbContext db) : IEnterpriseDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.EnsureCreatedAsync(cancellationToken);
    }

    private sealed class CreateLocalAccounts(LocalAccountsDbContext db) : ILocalAccountsDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.EnsureCreatedAsync(cancellationToken);
    }
}

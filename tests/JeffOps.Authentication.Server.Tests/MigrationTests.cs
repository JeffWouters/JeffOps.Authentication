using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Delegation.Infrastructure;
using JeffOps.Authentication.Delegation.SqlServer;
using JeffOps.Authentication.Enterprise.Infrastructure;
using JeffOps.Authentication.Enterprise.SqlServer;
using JeffOps.Authentication.Infrastructure.DependencyInjection;
using JeffOps.Authentication.Infrastructure.Persistence;
using JeffOps.Authentication.LocalAccounts.Infrastructure;
using JeffOps.Authentication.LocalAccounts.SqlServer;
using JeffOps.Authentication.Persistence.SqlServer;
using JeffOps.Authentication.Tenancy.Infrastructure;
using JeffOps.Authentication.Tenancy.SqlServer;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

public sealed class MigrationTests
{
    /// <summary>A model change without its migration would ship a schema the code doesn't match. No database needed.</summary>
    [Fact]
    public void Every_model_matches_its_sql_server_migrations()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:authentication"] = "Server=(unused);Database=unused" })
            .Build();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddJeffOpsAuthentication(configuration).AddSqlServerPersistence();
        JeffOps.Authentication.Testing.TestKeyRing.AddTestKeyRing(services);
        var modules = new AuthenticationBuilder(services, configuration);
        modules.AddDelegation().AddSqlServerPersistence();
        modules.AddEnterprise().AddSqlServerPersistence();
        modules.AddLocalAccounts().AddSqlServerPersistence();
        modules.AddTenancy().AddSqlServerPersistence();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        DbContext[] contexts =
        [
            scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>(),
            scope.ServiceProvider.GetRequiredService<DelegationDbContext>(),
            scope.ServiceProvider.GetRequiredService<EnterpriseDbContext>(),
            scope.ServiceProvider.GetRequiredService<LocalAccountsDbContext>(),
            scope.ServiceProvider.GetRequiredService<TenancyDbContext>(),
        ];

        foreach (var context in contexts)
        {
            context.Database.HasPendingModelChanges().ShouldBeFalse($"{context.GetType().Name} changed without a migration: run dotnet ef migrations add.");
        }
    }

    /// <summary>Rows written before names were stored normalized get them from the migration, and stay unique by them.</summary>
    [Fact]
    public async Task On_sql_server_existing_scim_names_are_normalized_by_the_migration()
    {
        Assert.SkipUnless(TestDatabase.SqlServer, "Runs with JEFFOPS_TEST_DATABASE=SqlServer.");
        var connectionString = await TestDatabase.CreateSqlServerAsync("migration", TestContext.Current.CancellationToken);
        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:authentication"] = connectionString })
                .Build();
            var services = new ServiceCollection();
            services.AddSingleton<IConfiguration>(configuration);
            new AuthenticationBuilder(services, configuration).AddEnterprise().AddSqlServerPersistence();
            await using var provider = services.BuildServiceProvider();
            await using var scope = provider.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<EnterpriseDbContext>();
            var migrator = db.GetInfrastructure().GetRequiredService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>();

            await migrator.MigrateAsync("20261017084646_ScimExternalIdCaseExact", TestContext.Current.CancellationToken);
            var tenant = Guid.NewGuid();
            await db.Database.ExecuteSqlAsync($"""
                INSERT INTO [enterprise].[ScimUsers] ([TenantId], [AccountId], [CreatedAccount], [DisabledAccount], [UserName], [Active], [Created], [LastModified], [Version])
                VALUES ({tenant}, {Guid.NewGuid()}, 0, 0, N'Jo.Doe@Contoso.COM', 1, SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET(), 1);
                INSERT INTO [enterprise].[ScimGroups] ([Id], [TenantId], [DisplayName], [Created], [LastModified], [Version])
                VALUES ({Guid.NewGuid()}, {tenant}, N'Engineers EU', SYSDATETIMEOFFSET(), SYSDATETIMEOFFSET(), 1);
                """, TestContext.Current.CancellationToken);

            await migrator.MigrateAsync(cancellationToken: TestContext.Current.CancellationToken);

            (await db.ScimUsers.SingleAsync(TestContext.Current.CancellationToken)).NormalizedUserName.ShouldBe("jo.doe@contoso.com");
            (await db.ScimGroups.SingleAsync(TestContext.Current.CancellationToken)).NormalizedDisplayName.ShouldBe("engineers eu");
            await Should.ThrowAsync<DbUpdateException>(async () =>
            {
                var duplicate = Enterprise.Domain.ScimUser.Provision(tenant, Guid.NewGuid(), createdAccount: false, DateTimeOffset.UtcNow);
                duplicate.Update("JO.DOE@contoso.com", null, null, null, null, active: true, DateTimeOffset.UtcNow);
                db.ScimUsers.Add(duplicate);
                await db.SaveChangesAsync(TestContext.Current.CancellationToken);
            });
        }
        finally
        {
            await TestDatabase.DeleteAsync(connectionString);
        }
    }

    [Fact]
    public async Task On_sql_server_the_hosts_apply_every_migration()
    {
        Assert.SkipUnless(TestDatabase.SqlServer, "Runs with JEFFOPS_TEST_DATABASE=SqlServer.");
        await using var host = await TokenServerHost.StartAsync();

        await using var scope = host.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>().Database;
        database.ProviderName.ShouldBe("Microsoft.EntityFrameworkCore.SqlServer");
        (await database.GetPendingMigrationsAsync(TestContext.Current.CancellationToken)).ShouldBeEmpty();
        (await database.GetAppliedMigrationsAsync(TestContext.Current.CancellationToken)).ShouldNotBeEmpty();
    }
}

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
using JeffOps.Authentication.Tests.Shared;
using Microsoft.EntityFrameworkCore;
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
        var modules = new AuthenticationBuilder(services, configuration);
        modules.AddDelegation().AddSqlServerPersistence();
        modules.AddEnterprise().AddSqlServerPersistence();
        modules.AddLocalAccounts().AddSqlServerPersistence();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        DbContext[] contexts =
        [
            scope.ServiceProvider.GetRequiredService<AuthenticationDbContext>(),
            scope.ServiceProvider.GetRequiredService<DelegationDbContext>(),
            scope.ServiceProvider.GetRequiredService<EnterpriseDbContext>(),
            scope.ServiceProvider.GetRequiredService<LocalAccountsDbContext>(),
        ];

        foreach (var context in contexts)
        {
            context.Database.HasPendingModelChanges().ShouldBeFalse($"{context.GetType().Name} changed without a migration: run dotnet ef migrations add.");
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

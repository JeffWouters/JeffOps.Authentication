using JeffOps.Authentication.Tests.Shared;
using JeffOps.Authorization.Infrastructure.DependencyInjection;
using JeffOps.Authorization.Infrastructure.Persistence;
using JeffOps.Authorization.Persistence.SqlServer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authorization.Management.Tests;

public sealed class MigrationTests
{
    /// <summary>A model change without its migration would ship a schema the code doesn't match. No database needed.</summary>
    [Fact]
    public void The_model_matches_its_sql_server_migrations()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:authorization"] = "Server=(unused);Database=unused" })
            .Build();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddJeffOpsAuthorization(configuration).AddSqlServerPersistence();

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();

        scope.ServiceProvider.GetRequiredService<AuthorizationDbContext>().Database.HasPendingModelChanges()
            .ShouldBeFalse("The authorization model changed without a migration: run dotnet ef migrations add.");
    }

    [Fact]
    public async Task On_sql_server_the_host_applies_every_migration()
    {
        Assert.SkipUnless(TestDatabase.SqlServer, "Runs with JEFFOPS_TEST_DATABASE=SqlServer.");
        await using var host = await ManagementHost.StartAsync();

        await using var scope = host.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AuthorizationDbContext>().Database;
        database.ProviderName.ShouldBe("Microsoft.EntityFrameworkCore.SqlServer");
        (await database.GetPendingMigrationsAsync(TestContext.Current.CancellationToken)).ShouldBeEmpty();
    }
}

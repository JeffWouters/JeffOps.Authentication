using JeffOps.Authentication.Server.Tests.Performance;
using JeffOps.Authorization.Application.Management;
using JeffOps.Authorization.Contracts;
using Microsoft.Extensions.DependencyInjection;
using static JeffOps.Authorization.Management.Tests.ManagementHost;

namespace JeffOps.Authorization.Management.Tests;

/// <summary>
/// Counts the database commands of the management service's own reads (see the server tests' RoundTripProbe). Runs only with
/// <c>JEFFOPS_PROBE=1</c>, alone, and writes its report to <c>JEFFOPS_PROBE_REPORT</c>.
/// </summary>
public sealed class RoundTripProbe
{
    public static bool Enabled => Environment.GetEnvironmentVariable("JEFFOPS_PROBE") == "1";

    [Fact(SkipUnless = nameof(Enabled), Skip = "Set JEFFOPS_PROBE=1 to run the round-trip probe.")]
    public async Task Measure_round_trips_of_the_management_reads()
    {
        await using var host = await StartAsync();
        var user = Guid.NewGuid();
        var roles = new List<RoleDto>();
        for (var index = 0; index < 5; index++)
        {
            roles.Add(await host.ReadAsync<RoleDto>(await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.Roles,
                new CreateRoleRequest($"Probe role {index}", ["billing.invoices.read"]))));
        }

        foreach (var role in roles)
        {
            (await host.SendAsync(RootUser(), HttpMethod.Post, ManagementRoutes.Assignments, new AssignRoleRequest(user, role.Id, TenantA))).EnsureSuccessStatusCode();
        }

        using var counter = new QueryCounter();
        var lines = new List<string> { $"# Management round trips ({(Authentication.Tests.Shared.TestDatabase.SqlServer ? "SQL Server" : "SQLite")})", "", "| Read | Commands |", "|---|---:|" };

        async Task MeasureAsync(string name, Func<IServiceProvider, Task> read)
        {
            await using (var warm = host.Services.CreateAsyncScope())
            {
                await read(warm.ServiceProvider);
            }

            await using var scope = host.Services.CreateAsyncScope();
            counter.Reset();
            await read(scope.ServiceProvider);
            lines.Add($"| {name} | {counter.Commands.Count} |");
        }

        await MeasureAsync($"HeldPermissions.OfAsync ({roles.Count} assignments)", services =>
            services.GetRequiredService<HeldPermissions>().OfAsync(user, TenantA, "tenant", null, TestContext.Current.CancellationToken));
        await MeasureAsync("Read API: GetUserAssignments", services =>
            services.GetRequiredService<IAuthorizationDataSource>().GetUserAssignmentsAsync(user, TenantA, TestContext.Current.CancellationToken));
        await MeasureAsync("Read API: GetRolePermissions", services =>
            services.GetRequiredService<IAuthorizationDataSource>().GetRolePermissionsAsync(TestContext.Current.CancellationToken));

        var path = Environment.GetEnvironmentVariable("JEFFOPS_PROBE_REPORT") ?? Path.Combine(Path.GetTempPath(), "jeffops-management-roundtrips.md");
        await File.WriteAllLinesAsync(path, lines, TestContext.Current.CancellationToken);
    }
}

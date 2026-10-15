using JeffOps.Authentication.Architecture.Tests.Infrastructure;

namespace JeffOps.Authentication.Architecture.Tests;

/// <summary>
/// Minimal APIs only (docs/DESIGN.md §6.1). BannedSymbols.txt already fails the build on ControllerBase; this also
/// catches attribute-routed classes and anything that slips past the analyzer (for example a Debug build).
/// </summary>
public sealed class MinimalApiTests
{
    [Fact]
    public void No_source_type_is_an_mvc_controller()
    {
        var controllers =
            from assembly in Repository.SourceAssemblies
            from type in assembly.GetTypes()
            where DerivesFrom(type, "Microsoft.AspNetCore.Mvc.ControllerBase")
                || type.GetCustomAttributes(inherit: true).Any(attribute =>
                    attribute.GetType().FullName == "Microsoft.AspNetCore.Mvc.ApiControllerAttribute")
            select type.FullName;

        controllers.ShouldBeEmpty();
    }

    private static bool DerivesFrom(Type type, string baseTypeFullName)
    {
        for (var current = type.BaseType; current is not null; current = current.BaseType)
        {
            if (current.FullName == baseTypeFullName)
            {
                return true;
            }
        }

        return false;
    }
}

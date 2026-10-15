using ArchUnitNET.Loader;
using ArchitectureModel = ArchUnitNET.Domain.Architecture;

namespace JeffOps.Authentication.Architecture.Tests.Infrastructure;

/// <summary>
/// The type-level model of every source assembly, built once with ArchUnitNET (reads IL, so method bodies count).
/// </summary>
internal static class SourceTypes
{
    public static ArchitectureModel Model { get; } =
        new ArchLoader().LoadAssemblies([.. Repository.SourceAssemblies]).Build();
}

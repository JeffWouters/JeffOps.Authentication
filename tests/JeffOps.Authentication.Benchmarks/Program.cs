using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Running;

namespace JeffOps.Authentication.Benchmarks;

/// <summary>
/// The hot paths, in process (docs/DESIGN.md §20). Run: <c>dotnet run -c Release -- --filter '*'</c>; set
/// <c>JEFFOPS_TEST_DATABASE=SqlServer</c> to run the token server benchmarks against SQL Server.
/// </summary>
public static class Program
{
    public static void Main(string[] args) =>
        BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args, DefaultConfig.Instance.AddDiagnoser(MemoryDiagnoser.Default));
}

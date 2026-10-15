using System.Text.Json;
using System.Xml.Linq;
using JeffOps.Authentication.Architecture.Tests.Infrastructure;

namespace JeffOps.Authentication.Architecture.Tests;

/// <summary>
/// Solution membership and the dependency licence policy (docs/DESIGN.md §6.5).
/// </summary>
public sealed class RepositoryHygieneTests
{
    [Fact]
    public void Every_project_is_in_the_solution()
    {
        var solution = XDocument.Load(Path.Combine(Repository.Root, Repository.SolutionFileName));
        var inSolution = solution.Descendants("Project")
            .Select(project => (string?)project.Attribute("Path"))
            .OfType<string>()
            .Select(path => Path.GetFileNameWithoutExtension(path.Replace('\\', '/')))
            .ToHashSet(StringComparer.Ordinal);

        Repository.AllProjects
            .Select(project => project.Name)
            .Where(name => !inSolution.Contains(name))
            .ShouldBeEmpty($"Add these projects to {Repository.SolutionFileName}.");
    }

    [Fact]
    public void No_project_resolves_a_banned_package_even_transitively()
    {
        var banned = File.ReadAllLines(Path.Combine(Repository.Root, "BannedPackages.txt"))
            .Select(line => line.Trim())
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var violations = new List<string>();
        foreach (var project in Repository.AllProjects)
        {
            var assetsFile = Path.Combine(Path.GetDirectoryName(project.FullPath)!, "obj", "project.assets.json");
            File.Exists(assetsFile).ShouldBeTrue($"{project.Name} has not been restored.");

            using var assets = JsonDocument.Parse(File.ReadAllText(assetsFile));
            violations.AddRange(
                from library in assets.RootElement.GetProperty("libraries").EnumerateObject()
                where library.Value.GetProperty("type").GetString() == "package"
                let id = library.Name.Split('/')[0]
                where banned.Contains(id)
                select $"{project.Name} -> {library.Name}");
        }

        violations.ShouldBeEmpty("Only free, permissively licensed packages are allowed (docs/DESIGN.md §6.5).");
    }

    [Fact]
    public void Banned_package_list_is_not_empty()
    {
        // The build guard and the test above both read this file; an empty or missing list would silently allow everything.
        File.ReadAllLines(Path.Combine(Repository.Root, "BannedPackages.txt"))
            .Count(line => line.Trim() is { Length: > 0 } trimmed && !trimmed.StartsWith('#'))
            .ShouldBeGreaterThan(0);
    }
}

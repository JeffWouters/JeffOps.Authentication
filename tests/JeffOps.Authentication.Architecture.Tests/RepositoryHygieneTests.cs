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

    /// <summary>Licence expressions a dependency may carry (docs/DESIGN.md §6.5).</summary>
    private static readonly HashSet<string> PermissiveLicences = new(StringComparer.OrdinalIgnoreCase)
    {
        "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "MS-PL",
    };

    /// <summary>
    /// Packages that predate licence expressions and only carry a URL; each is checked by hand and listed with its licence.
    /// </summary>
    private static readonly Dictionary<string, string> CheckedLicenceUrls = new(StringComparer.OrdinalIgnoreCase)
    {
        ["https://github.com/dotnet/corefx/blob/master/LICENSE.TXT"] = "MIT (.NET Foundation)",
        ["https://github.com/dotnet/runtime/blob/main/LICENSE.TXT"] = "MIT (.NET Foundation)",
        ["http://go.microsoft.com/fwlink/?LinkId=329770"] = "MIT (.NET library licence, relicensed MIT with .NET Core)",
        ["https://dotnet.microsoft.com/en-us/dotnet_library_license.htm"] = "MIT (.NET library licence, relicensed MIT with .NET Core)",
    };

    /// <summary>
    /// Free Microsoft runtime components under the Microsoft Software License Terms (redistributable, no fee, not open source)
    /// that SQL Server support cannot do without. Each is an explicit, reviewed exception (docs/DESIGN.md §6.5, D24).
    /// </summary>
    private static readonly Dictionary<string, string> AcceptedProprietaryRuntimes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Microsoft.Data.SqlClient.SNI.runtime"] = "SQL Server native networking, required by Microsoft.Data.SqlClient",
        ["Microsoft.Identity.Client.NativeInterop"] = "MSAL broker interop, required by Microsoft.Data.SqlClient's Entra authentication",
    };

    [Fact]
    public void Every_resolved_package_has_a_permissive_licence()
    {
        var violations = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var project in Repository.AllProjects)
        {
            var assetsFile = Path.Combine(Path.GetDirectoryName(project.FullPath)!, "obj", "project.assets.json");
            File.Exists(assetsFile).ShouldBeTrue($"{project.Name} has not been restored.");

            using var assets = JsonDocument.Parse(File.ReadAllText(assetsFile));
            var folders = assets.RootElement.GetProperty("packageFolders").EnumerateObject().Select(folder => folder.Name).ToList();
            foreach (var library in assets.RootElement.GetProperty("libraries").EnumerateObject()
                .Where(library => library.Value.GetProperty("type").GetString() == "package"))
            {
                var path = library.Value.GetProperty("path").GetString()!;
                var id = library.Name.Split('/')[0];
                if (AcceptedProprietaryRuntimes.ContainsKey(id))
                {
                    continue;
                }

                var nuspec = folders
                    .Select(folder => Path.Combine(folder, path, id.ToLowerInvariant() + ".nuspec"))
                    .FirstOrDefault(File.Exists);
                if (nuspec is null)
                {
                    violations.Add($"{library.Name}: nuspec not found");
                    continue;
                }

                var metadata = XDocument.Load(nuspec).Root!.Elements().First(element => element.Name.LocalName == "metadata");
                var license = metadata.Elements().FirstOrDefault(element => element.Name.LocalName == "license");
                var licenseUrl = metadata.Elements().FirstOrDefault(element => element.Name.LocalName == "licenseUrl")?.Value.Trim();

                var allowed = license?.Attribute("type")?.Value == "expression"
                    ? license.Value.Split([" OR ", " or "], StringSplitOptions.TrimEntries).Any(PermissiveLicences.Contains)
                    : licenseUrl is not null && CheckedLicenceUrls.ContainsKey(licenseUrl);
                if (!allowed)
                {
                    violations.Add($"{library.Name}: {license?.Value ?? licenseUrl ?? "no licence"}");
                }
            }
        }

        violations.ShouldBeEmpty("Every dependency, direct or transitive, must be permissively licensed (docs/DESIGN.md §6.5).");
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

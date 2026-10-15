using System.Reflection;
using System.Xml.Linq;

namespace JeffOps.Authentication.Architecture.Tests.Infrastructure;

/// <summary>
/// A project as declared in its .csproj: direct references only. Directory.Build.props items are not included.
/// </summary>
internal sealed record ProjectInfo(
    string Name,
    string FullPath,
    IReadOnlyList<string> ProjectReferences,
    IReadOnlyList<string> PackageReferences,
    IReadOnlyList<string> FrameworkReferences);

/// <summary>
/// Reads the repository from disk so rules check what is declared, not what the compiler happened to keep.
/// (The compiler drops references a project doesn't use yet, so assembly metadata under-reports them.)
/// </summary>
internal static class Repository
{
    public const string SolutionFileName = "JeffOps.Authentication.slnx";

    public static string Root { get; } = FindRoot();

    public static IReadOnlyList<ProjectInfo> SourceProjects { get; } = LoadProjects(Path.Combine(Root, "src"));

    public static IReadOnlyList<ProjectInfo> TestProjects { get; } = LoadProjects(Path.Combine(Root, "tests"));

    public static IReadOnlyList<ProjectInfo> AllProjects { get; } = [.. SourceProjects, .. TestProjects];

    public static IReadOnlyList<Assembly> SourceAssemblies { get; } =
        [.. SourceProjects.Select(project => Assembly.Load(new AssemblyName(project.Name)))];

    private static readonly Dictionary<string, ProjectInfo> ByName = AllProjects.ToDictionary(project => project.Name);

    /// <summary>All projects reachable from <paramref name="project"/> through project references, excluding itself.</summary>
    public static IReadOnlySet<string> TransitiveReferences(ProjectInfo project)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var pending = new Stack<string>(project.ProjectReferences);

        while (pending.TryPop(out var name))
        {
            if (seen.Add(name) && ByName.TryGetValue(name, out var referenced))
            {
                foreach (var next in referenced.ProjectReferences)
                {
                    pending.Push(next);
                }
            }
        }

        return seen;
    }

    private static string FindRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, SolutionFileName)))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException($"Repository root ({SolutionFileName}) not found above {AppContext.BaseDirectory}.");
    }

    private static List<ProjectInfo> LoadProjects(string directory) =>
        [.. Directory.EnumerateFiles(directory, "*.csproj", SearchOption.AllDirectories)
            .Where(path => !IsBuildOutput(path))
            .Select(Parse)
            .OrderBy(project => project.Name, StringComparer.Ordinal)];

    private static bool IsBuildOutput(string path)
    {
        var segments = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return segments.Contains("bin") || segments.Contains("obj");
    }

    private static ProjectInfo Parse(string path)
    {
        var document = XDocument.Load(path);

        string[] Includes(string itemName) =>
            [.. document.Descendants(itemName).Select(item => (string?)item.Attribute("Include")).OfType<string>()];

        return new ProjectInfo(
            Path.GetFileNameWithoutExtension(path),
            path,
            [.. Includes("ProjectReference").Select(reference => Path.GetFileNameWithoutExtension(reference.Replace('\\', '/')))],
            Includes("PackageReference"),
            Includes("FrameworkReference"));
    }
}

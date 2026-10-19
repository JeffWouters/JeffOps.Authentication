using System.Text.RegularExpressions;
using JeffOps.Authentication.Architecture.Tests.Infrastructure;

namespace JeffOps.Authentication.Architecture.Tests;

/// <summary>
/// Log event ids identify one message each, across every package: alerts and log queries key on them, so a reused id makes
/// one event look like another.
/// </summary>
public sealed partial class LoggingTests
{
    [Fact]
    public void Every_logger_message_has_its_own_event_id()
    {
        var source = Path.Combine(Repository.Root, "src");
        var ids =
            from path in Directory.EnumerateFiles(source, "*.cs", SearchOption.AllDirectories)
            let segments = path.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            where !segments.Contains("bin") && !segments.Contains("obj")
            from Match match in EventId().Matches(File.ReadAllText(path))
            select (Id: int.Parse(match.Groups["id"].Value, System.Globalization.CultureInfo.InvariantCulture), File: Path.GetRelativePath(Repository.Root, path));

        var all = ids.ToList();
        all.ShouldNotBeEmpty("the scan should find the [LoggerMessage] attributes in src");
        all.GroupBy(entry => entry.Id)
            .Where(group => group.Count() > 1)
            .Select(group => $"{group.Key}: {string.Join(", ", group.Select(entry => entry.File))}")
            .ShouldBeEmpty("each [LoggerMessage] needs a unique EventId");
    }

    [GeneratedRegex(@"\[LoggerMessage\s*\([^)]*?\bEventId\s*=\s*(?<id>\d+)")]
    private static partial Regex EventId();
}

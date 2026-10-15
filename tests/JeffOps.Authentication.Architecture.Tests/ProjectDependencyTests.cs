using JeffOps.Authentication.Architecture.Tests.Infrastructure;

namespace JeffOps.Authentication.Architecture.Tests;

/// <summary>
/// Project-level dependency rules (docs/DESIGN.md §6.3), checked on the transitive closure of project references.
/// </summary>
public sealed class ProjectDependencyTests
{
    public static TheoryData<string> SourceProjects => [.. Repository.SourceProjects.Select(project => project.Name)];

    [Fact]
    public void Every_source_project_has_a_known_role() =>
        Repository.SourceProjects
            .Where(project => ProjectKinds.Classify(project.Name) is null)
            .Select(project => project.Name)
            .ShouldBeEmpty("Classify every new project in ProjectKinds.Classify (docs/DESIGN.md §6.2).");

    [Theory]
    [MemberData(nameof(SourceProjects))]
    public void Project_references_respect_the_layering(string projectName)
    {
        var project = Repository.SourceProjects.Single(candidate => candidate.Name == projectName);
        var kind = ProjectKinds.KindOf(project.Name);
        var context = ProjectKinds.BoundedContextOf(project.Name);
        var closure = Repository.TransitiveReferences(project);

        var violations = closure.Where(reference => !IsAllowed(kind, context, reference)).ToList();

        violations.ShouldBeEmpty($"{project.Name} ({kind}) may not depend on these projects (docs/DESIGN.md §6.3).");
    }

    [Theory]
    [MemberData(nameof(SourceProjects))]
    public void Authorization_does_not_depend_on_authentication_internals(string projectName)
    {
        if (!projectName.StartsWith("JeffOps.Authorization.", StringComparison.Ordinal))
        {
            return;
        }

        var project = Repository.SourceProjects.Single(candidate => candidate.Name == projectName);

        Repository.TransitiveReferences(project)
            .Where(reference => reference.StartsWith("JeffOps.Authentication.", StringComparison.Ordinal)
                && ProjectKinds.KindOf(reference) != ProjectKind.Kernel)
            .ShouldBeEmpty("Authorization must work with any token issuer that satisfies the claims contract (docs/DESIGN.md §6.3, §10).");
    }

    [Theory]
    [MemberData(nameof(SourceProjects))]
    public void Domain_contracts_and_application_reference_no_frameworks_or_infrastructure_packages(string projectName)
    {
        var kind = ProjectKinds.KindOf(projectName);
        if (kind is not (ProjectKind.Domain or ProjectKind.Contracts or ProjectKind.Application))
        {
            return;
        }

        var project = Repository.SourceProjects.Single(candidate => candidate.Name == projectName);

        project.FrameworkReferences.ShouldBeEmpty($"{projectName} must not reference ASP.NET Core or other shared frameworks.");
        project.PackageReferences
            .Where(package => !(package == "Microsoft.Extensions.Options"
                || (package.StartsWith("Microsoft.Extensions.", StringComparison.Ordinal) && package.EndsWith(".Abstractions", StringComparison.Ordinal))))
            .ShouldBeEmpty($"{projectName} may only reference Microsoft.Extensions.Options and Microsoft.Extensions.*.Abstractions packages.");
    }

    [Theory]
    [MemberData(nameof(SourceProjects))]
    public void Only_infrastructure_references_entity_framework(string projectName)
    {
        var kind = ProjectKinds.KindOf(projectName);
        if (kind is ProjectKind.Infrastructure or ProjectKind.FeatureModule)
        {
            return;
        }

        var project = Repository.SourceProjects.Single(candidate => candidate.Name == projectName);

        project.PackageReferences
            .Where(package => package.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.Ordinal))
            .ShouldBeEmpty($"{projectName} ({kind}) must not reference EF Core.");
    }

    private static bool IsAllowed(ProjectKind kind, string? context, string reference)
    {
        var referenceKind = ProjectKinds.KindOf(reference);
        var sameContext = ProjectKinds.BoundedContextOf(reference) == context;

        return kind switch
        {
            ProjectKind.Kernel => false,
            ProjectKind.Domain => reference == ProjectKinds.SharedKernel,
            ProjectKind.Contracts => referenceKind == ProjectKind.Kernel
                || (referenceKind == ProjectKind.Domain && sameContext),
            ProjectKind.Application => referenceKind == ProjectKind.Kernel
                || (sameContext && referenceKind is ProjectKind.Domain or ProjectKind.Contracts),
            ProjectKind.Infrastructure => referenceKind is ProjectKind.Kernel
                || (sameContext && referenceKind is ProjectKind.Domain or ProjectKind.Contracts or ProjectKind.Application or ProjectKind.Infrastructure),
            ProjectKind.Presentation => referenceKind is ProjectKind.Kernel
                || (sameContext && referenceKind is ProjectKind.Domain or ProjectKind.Contracts or ProjectKind.Application),
            ProjectKind.Plugin or ProjectKind.FeatureModule => referenceKind == ProjectKind.Kernel
                || (reference.StartsWith("JeffOps.Authentication.", StringComparison.Ordinal)
                    && referenceKind is ProjectKind.Domain or ProjectKind.Contracts or ProjectKind.Application),
            ProjectKind.ClientAdapter or ProjectKind.Common => referenceKind is ProjectKind.Kernel
                or ProjectKind.ClientAdapter or ProjectKind.Common or ProjectKind.Contracts
                || (referenceKind == ProjectKind.Domain && reference.StartsWith("JeffOps.Authorization.", StringComparison.Ordinal)),
            _ => false,
        };
    }
}

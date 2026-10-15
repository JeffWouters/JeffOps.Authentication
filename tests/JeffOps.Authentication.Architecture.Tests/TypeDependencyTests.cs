using JeffOps.Authentication.Architecture.Tests.Infrastructure;

namespace JeffOps.Authentication.Architecture.Tests;

/// <summary>
/// Type-level rules (docs/DESIGN.md §6.1, §6.3). Project references can't see these: a project may legally reference
/// an assembly yet use a forbidden namespace from it, and slices live side by side in one project.
/// </summary>
public sealed class TypeDependencyTests
{
    private static readonly string[] ForbiddenInCore =
    [
        "Microsoft.AspNetCore",
        "Microsoft.EntityFrameworkCore",
        "OpenIddict",
        "Azure",
        "System.Net.Http",
        "Yarp",
    ];

    private static readonly string[] FeatureModules =
    [
        "JeffOps.Authentication.LocalAccounts",
        "JeffOps.Authentication.Delegation",
        "JeffOps.Authentication.Enterprise",
    ];

    /// <summary>Allowed layer-to-layer use inside a feature module's single project (D17).</summary>
    private static readonly Dictionary<string, string[]> AllowedModuleLayers = new(StringComparer.Ordinal)
    {
        ["Domain"] = ["Domain"],
        ["Application"] = ["Domain", "Application"],
        ["Infrastructure"] = ["Domain", "Application", "Infrastructure"],
        ["Endpoints"] = ["Domain", "Application", "Endpoints"],
    };

    [Fact]
    public void Domain_contracts_and_application_types_use_no_framework_or_infrastructure_namespaces()
    {
        var violations =
            from type in SourceTypes.Model.Types
            let kind = ProjectKinds.Classify(type.Assembly.Name.Split(',')[0])
            where kind is ProjectKind.Domain or ProjectKind.Contracts or ProjectKind.Application
            from dependency in type.Dependencies
            let target = dependency.Target.Namespace.FullName
            where ForbiddenInCore.Any(prefix => target == prefix || target.StartsWith(prefix + ".", StringComparison.Ordinal))
            select $"{type.FullName} -> {dependency.Target.FullName}";

        violations.Distinct().ShouldBeEmpty();
    }

    [Fact]
    public void Slices_do_not_depend_on_other_slices()
    {
        var violations =
            from type in SourceTypes.Model.Types
            let fromSlice = SlicePath.Of(type.Namespace.FullName)
            where fromSlice is not null
            from dependency in type.Dependencies
            let toSlice = SlicePath.Of(dependency.Target.Namespace.FullName)
            where toSlice is not null
                && dependency.Target.FullName.StartsWith("JeffOps.", StringComparison.Ordinal)
                && !SlicePath.AreOnTheSameBranch(fromSlice, toSlice)
            select $"{type.FullName} -> {dependency.Target.FullName}";

        violations.Distinct().ShouldBeEmpty("Slices share only Domain types and ports (docs/DESIGN.md §6.1).");
    }

    [Fact]
    public void Feature_module_layers_follow_the_dependency_rule()
    {
        var violations =
            from type in SourceTypes.Model.Types
            let module = FeatureModules.SingleOrDefault(name => type.Namespace.FullName.StartsWith(name + ".", StringComparison.Ordinal))
            where module is not null
            let fromLayer = LayerOf(module, type.Namespace.FullName)
            where fromLayer is not null
            from dependency in type.Dependencies
            let toLayer = LayerOf(module, dependency.Target.Namespace.FullName)
            where toLayer is not null && !AllowedModuleLayers[fromLayer].Contains(toLayer)
            select $"{type.FullName} ({fromLayer}) -> {dependency.Target.FullName} ({toLayer})";

        violations.Distinct().ShouldBeEmpty("Layer folders in a feature module follow the same rules as layer projects (D17).");
    }

    [Fact]
    public void Slice_paths_allow_the_same_branch_only()
    {
        // Guards the helper the slice rule depends on, since the rule passes vacuously while there are no slices.
        string[] createPat = ["PersonalAccessTokens", "CreatePat"];
        string[] revokePat = ["PersonalAccessTokens", "RevokePat"];
        string[] patArea = ["PersonalAccessTokens"];
        string[] accounts = ["Accounts", "Register"];

        SlicePath.Of("JeffOps.Authentication.Application.Features.PersonalAccessTokens.CreatePat").ShouldBe(createPat);
        SlicePath.Of("JeffOps.Authentication.Application.Grants").ShouldBeNull();
        SlicePath.AreOnTheSameBranch(createPat, patArea).ShouldBeTrue();
        SlicePath.AreOnTheSameBranch(patArea, createPat).ShouldBeTrue();
        SlicePath.AreOnTheSameBranch(createPat, revokePat).ShouldBeFalse();
        SlicePath.AreOnTheSameBranch(createPat, accounts).ShouldBeFalse();
    }

    private static string? LayerOf(string module, string @namespace)
    {
        if (!@namespace.StartsWith(module + ".", StringComparison.Ordinal))
        {
            return null;
        }

        var layer = @namespace[(module.Length + 1)..].Split('.')[0];
        return AllowedModuleLayers.ContainsKey(layer) ? layer : null;
    }
}

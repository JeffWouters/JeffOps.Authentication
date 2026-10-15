namespace JeffOps.Authentication.Architecture.Tests.Infrastructure;

/// <summary>
/// Role of a source project in the architecture (docs/DESIGN.md §6.2).
/// </summary>
internal enum ProjectKind
{
    /// <summary>SharedKernel and Abstractions: referenced by everything, reference nothing.</summary>
    Kernel,

    Domain,

    /// <summary>Wire contracts (DTOs, integration events) of a bounded context; pure like Domain.</summary>
    Contracts,

    Application,

    /// <summary>Infrastructure and Persistence.* projects.</summary>
    Infrastructure,

    /// <summary>Endpoints and UI projects.</summary>
    Presentation,

    /// <summary>Implements a port of a layered module (KeyVault, Federation.*).</summary>
    Plugin,

    /// <summary>Optional feature module: one project, one folder per layer (D17).</summary>
    FeatureModule,

    /// <summary>Used by resource services and browsers; never sees server internals.</summary>
    ClientAdapter,

    /// <summary>Cross-cutting helpers without business rules.</summary>
    Common,
}

internal static class ProjectKinds
{
    public const string SharedKernel = "JeffOps.Authentication.SharedKernel";
    public const string Abstractions = "JeffOps.Authentication.Abstractions";

    /// <summary>
    /// Classifies a project by name. Returns null for an unknown project, which fails
    /// <see cref="ProjectDependencyTests.Every_source_project_has_a_known_role"/>: adding a project means deciding its role here.
    /// </summary>
    public static ProjectKind? Classify(string name) => name switch
    {
        SharedKernel or Abstractions => ProjectKind.Kernel,
        "JeffOps.Authentication.KeyVault" => ProjectKind.Plugin,
        _ when name.StartsWith("JeffOps.Authentication.Federation.", StringComparison.Ordinal) => ProjectKind.Plugin,
        "JeffOps.Authentication.LocalAccounts" or "JeffOps.Authentication.Delegation" or "JeffOps.Authentication.Enterprise" => ProjectKind.FeatureModule,
        // A feature module's provider package (migrations), for example JeffOps.Authentication.Delegation.SqlServer.
        _ when name.StartsWith("JeffOps.Authentication.LocalAccounts.", StringComparison.Ordinal)
            || name.StartsWith("JeffOps.Authentication.Delegation.", StringComparison.Ordinal)
            || name.StartsWith("JeffOps.Authentication.Enterprise.", StringComparison.Ordinal) => ProjectKind.FeatureModule,
        "JeffOps.Authentication.Client" or "JeffOps.Authentication.Bff" or "JeffOps.Authentication.Bff.Yarp"
            or "JeffOps.Authorization.AspNetCore" => ProjectKind.ClientAdapter,
        "JeffOps.Security.AspNetCore" or "JeffOps.Entitlements" or "JeffOps.Authentication.Testing" => ProjectKind.Common,
        _ when name.EndsWith(".Domain", StringComparison.Ordinal) => ProjectKind.Domain,
        _ when name.EndsWith(".Contracts", StringComparison.Ordinal) => ProjectKind.Contracts,
        _ when name.EndsWith(".Application", StringComparison.Ordinal) => ProjectKind.Application,
        _ when name.EndsWith(".Infrastructure", StringComparison.Ordinal)
            || name.Contains(".Persistence.", StringComparison.Ordinal) => ProjectKind.Infrastructure,
        _ when name.EndsWith(".Endpoints", StringComparison.Ordinal)
            || name.EndsWith(".UI", StringComparison.Ordinal) => ProjectKind.Presentation,
        _ => null,
    };

    public static ProjectKind KindOf(string name) =>
        Classify(name) ?? throw new InvalidOperationException($"{name} has no role in ProjectKinds.Classify.");

    /// <summary>"Authentication" or "Authorization" for layered-module projects, else null.</summary>
    public static string? BoundedContextOf(string name) =>
        name.StartsWith("JeffOps.Authorization.", StringComparison.Ordinal) ? "Authorization"
        : name.StartsWith("JeffOps.Authentication.", StringComparison.Ordinal) ? "Authentication"
        : null;
}

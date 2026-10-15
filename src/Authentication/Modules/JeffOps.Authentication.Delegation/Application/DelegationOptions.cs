namespace JeffOps.Authentication.Delegation.Application;

/// <summary>Delegated access (docs/DESIGN.md §12). Bound from <see cref="SectionName"/>.</summary>
public sealed class DelegationOptions
{
    public const string SectionName = "JeffOps:Delegation";

    /// <summary>The extension grant name of impersonation tokens: grant type <c>{ExtensionGrantNamespace}:impersonation</c>.</summary>
    public const string ImpersonationGrant = "impersonation";

    /// <summary>The extension grant name of tenant-switch tokens: grant type <c>{ExtensionGrantNamespace}:tenant-switch</c>.</summary>
    public const string TenantSwitchGrant = "tenant-switch";

    public ImpersonationOptions Impersonation { get; } = new();

    public TenantAccessOptions TenantAccess { get; } = new();

    /// <summary>Whether requesting and deciding delegated access needs a stepped-up (multi-factor) sign-in. Default: true.</summary>
    public bool RequireStepUp { get; set; } = true;
}

public sealed class ImpersonationOptions
{
    /// <summary>How long the target has to approve. Default: 5 minutes.</summary>
    public TimeSpan ApprovalWindow { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>How long an approved grant lasts. Default: 30 minutes.</summary>
    public TimeSpan SessionWindow { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>The lifetime of each impersonation token; clients mint again before it ends. Default: 3 minutes.</summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromMinutes(3);

    /// <summary>The authorization policy a user needs to request impersonation. Default: <c>auth.impersonation.initiate</c>.</summary>
    public string InitiatePolicy { get; set; } = "auth.impersonation.initiate";

    /// <summary>The authorization policy platform staff need for break-glass. Default: <c>auth.impersonation.breakglass</c>.</summary>
    public string BreakGlassPolicy { get; set; } = "auth.impersonation.breakglass";
}

public sealed class TenantAccessOptions
{
    /// <summary>How long a tenant administrator has to approve a lockbox request. Default: 15 minutes.</summary>
    public TimeSpan ApprovalWindow { get; set; } = TimeSpan.FromMinutes(15);

    /// <summary>How long an approved lockbox grant lasts. Default: 60 minutes.</summary>
    public TimeSpan SessionWindow { get; set; } = TimeSpan.FromMinutes(60);

    /// <summary>The lifetime of each tenant-switch token; clients mint again before it ends. Default: 10 minutes.</summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// The authorization policy a tenant administrator needs to approve, deny or revoke lockbox access to their tenant.
    /// Default: <c>auth.tenant-access.approve</c>.
    /// </summary>
    public string ApprovePolicy { get; set; } = "auth.tenant-access.approve";
}

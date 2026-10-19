namespace JeffOps.Authorization.Application;

/// <summary>Authorization management (docs/DESIGN.md §11.5). Bound from <see cref="SectionName"/>.</summary>
public sealed class ManagementOptions
{
    public const string SectionName = "JeffOps:AuthorizationManagement";

    public ManagementPermissions Permissions { get; } = new();

    /// <summary>
    /// The delegation ceiling for callers acting in a managed tenant (a tenant switch carrying delegation scopes): what they may
    /// administer there is cut down exactly as resource services cut down what they may do. Default: <c>admin</c> lifts it,
    /// <c>readonly</c> allows actions ending in <c>read</c>. Set it to match the resource services' configuration.
    /// </summary>
    public Domain.Ceilings.DelegationCeiling DelegationCeiling { get; set; } = Domain.Ceilings.DelegationCeiling.Default;

    /// <summary>
    /// Permissions that make a role privileged, besides the management permissions themselves. Granting a privileged role
    /// requires holding all its permissions.
    /// </summary>
    public IList<string> AdditionalPrivilegedPermissions { get; } = [];

    /// <summary>
    /// Whether interactive users need a stepped-up (multi-factor) sign-in for management changes. Default: true.
    /// Impersonation sessions can never make management changes.
    /// </summary>
    public bool RequireStepUpForChanges { get; set; } = true;

    public TimeSpan BreakGlassMaxDuration { get; set; } = TimeSpan.FromHours(8);

    public TimeSpan MaxRecertifyExtension { get; set; } = TimeSpan.FromDays(365);

    /// <summary>How long a pending role change can still be approved; older requests can only be rejected. Default: 7 days.</summary>
    public TimeSpan RoleChangeRequestLifetime { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// Which permission domains each service may register, e.g. <c>svc-billing</c> → <c>billing</c>. A service without an
    /// entry may register the domain named after it (<c>svc-billing</c> → <c>billing</c>).
    /// </summary>
    public IDictionary<string, List<string>> RegistrationDomains { get; } = new Dictionary<string, List<string>>(StringComparer.Ordinal);

    public IReadOnlyCollection<string> PrivilegedPermissions() =>
        [Permissions.RolesWrite, Permissions.AssignmentsWrite, Permissions.PoliciesWrite, Permissions.ScopesWrite, Permissions.Register, .. AdditionalPrivilegedPermissions];
}

/// <summary>The permissions guarding management itself. Defaults use the <c>authorization</c> domain.</summary>
public sealed class ManagementPermissions
{
    public string RolesRead { get; set; } = "authorization.roles.read";

    public string RolesWrite { get; set; } = "authorization.roles.write";

    public string AssignmentsRead { get; set; } = "authorization.assignments.read";

    public string AssignmentsWrite { get; set; } = "authorization.assignments.write";

    public string PoliciesWrite { get; set; } = "authorization.policies.write";

    public string ScopesWrite { get; set; } = "authorization.scopes.write";

    /// <summary>Services registering their permission definitions.</summary>
    public string Register { get; set; } = "authorization.permissions.register";

    /// <summary>Resource services reading role, policy and scope data to decide locally.</summary>
    public string ReadApi { get; set; } = "authorization.decisions.read";
}

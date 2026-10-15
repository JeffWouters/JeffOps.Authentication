using JeffOps.Authentication.SharedKernel.Domain;
using JeffOps.Authorization.Domain.Permissions;

namespace JeffOps.Authorization.Domain.Management;

/// <summary>
/// A role: a named bundle of permissions. The scope is chosen per assignment, not by the role (docs/DESIGN.md §11.1).
/// Built-in roles come from the host's role provider and can't be edited or deleted; custom roles belong to one tenant.
/// </summary>
public sealed class Role : AggregateRoot<Guid>
{
    private readonly List<RolePermission> _permissions = [];

    private Role(Guid id, string name, Guid? tenantId, bool isBuiltIn, bool isSuperAdmin, bool isBreakGlass, string? minScopeKey, IReadOnlyCollection<string> complianceControls)
        : base(id)
    {
        Name = name;
        TenantId = tenantId;
        IsBuiltIn = isBuiltIn;
        IsSuperAdmin = isSuperAdmin;
        IsBreakGlass = isBreakGlass;
        MinScopeKey = string.IsNullOrWhiteSpace(minScopeKey) ? null : minScopeKey.Trim().ToLowerInvariant();
        ComplianceControls = string.Join(';', complianceControls.Where(control => !string.IsNullOrWhiteSpace(control)).Select(control => control.Trim()));
    }

    private Role()
    {
    }

    public string Name { get; private set; } = string.Empty;

    /// <summary>The tenant owning a custom role; null for global (built-in or Root-created) roles.</summary>
    public Guid? TenantId { get; private set; }

    public bool IsBuiltIn { get; private set; }

    /// <summary>Implies every permission (<c>*</c>).</summary>
    public bool IsSuperAdmin { get; private set; }

    /// <summary>Emergency access: may only be assigned time-boxed, and a non-Root grant waits for a second approver.</summary>
    public bool IsBreakGlass { get; private set; }

    /// <summary>The narrowest scope the role may be assigned at, e.g. an auditor role only at organization level.</summary>
    public string? MinScopeKey { get; private set; }

    /// <summary>Compliance controls the role satisfies (e.g. <c>SOC2:CC6.1</c>), separated by <c>;</c>.</summary>
    public string ComplianceControls { get; private set; } = string.Empty;

    public IReadOnlyCollection<RolePermission> Permissions => _permissions.AsReadOnly();

    public static Role Create(
        string name,
        Guid? tenantId,
        DateTimeOffset now,
        bool isBuiltIn = false,
        bool isSuperAdmin = false,
        bool isBreakGlass = false,
        string? minScopeKey = null,
        IReadOnlyCollection<string>? complianceControls = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        return new Role(Guid.CreateVersion7(now), name.Trim(), tenantId, isBuiltIn, isSuperAdmin, isBreakGlass, minScopeKey, complianceControls ?? []);
    }

    /// <summary>The codes the role grants, including <c>*</c> for a super-admin role.</summary>
    public IReadOnlyList<string> PermissionCodes() =>
        IsSuperAdmin ? [.. _permissions.Select(permission => permission.Code), Permission.Wildcard] : [.. _permissions.Select(permission => permission.Code)];

    public bool Grants(string permission) => PermissionSet.From(PermissionCodes()).Grants(permission);

    /// <summary>Adds a permission. Returns false when the role already had it.</summary>
    public bool AddPermission(string code)
    {
        var normalized = Permission.Normalize(code);
        if (_permissions.Any(permission => permission.Code == normalized))
        {
            return false;
        }

        _permissions.Add(new RolePermission(Id, normalized));
        Raise(new RolePermissionsChanged(Id));
        return true;
    }

    /// <summary>Removes a permission. Returns false when the role didn't have it.</summary>
    public bool RemovePermission(string code)
    {
        var normalized = Permission.Normalize(code);
        var removed = _permissions.RemoveAll(permission => permission.Code == normalized) > 0;
        if (removed)
        {
            Raise(new RolePermissionsChanged(Id));
        }

        return removed;
    }
}

/// <summary>One permission of a role.</summary>
public sealed class RolePermission
{
    internal RolePermission(Guid roleId, string code)
    {
        RoleId = roleId;
        Code = code;
    }

    private RolePermission()
    {
    }

    public Guid RoleId { get; private set; }

    public string Code { get; private set; } = string.Empty;
}

public sealed record RolePermissionsChanged(Guid RoleId) : IDomainEvent;

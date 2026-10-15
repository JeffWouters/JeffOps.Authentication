using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Application.Management;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Management;
using JeffOps.Authorization.Domain.Permissions;

namespace JeffOps.Authorization.Application.Features.Roles;

internal static class RoleMapping
{
    public static RoleDto ToDto(this Role role) => new(
        role.Id,
        role.Name,
        role.TenantId,
        role.IsBuiltIn,
        role.IsSuperAdmin,
        role.IsBreakGlass,
        role.MinScopeKey,
        role.ComplianceControls.Split(';', StringSplitOptions.RemoveEmptyEntries),
        [.. role.Permissions.Select(permission => permission.Code).Order(StringComparer.Ordinal)]);
}

// ---- ListRoles ---------------------------------------------------------------------------------------------------------

/// <summary>The roles the caller can see: global roles and their tenant's custom roles (Root sees all).</summary>
public sealed record ListRolesQuery(ManagementCaller Caller);

public sealed class ListRolesHandler(IRoleRepository roles, ManagementGuard guard) : IQueryHandler<ListRolesQuery, IReadOnlyList<RoleDto>>
{
    public async Task<Result<IReadOnlyList<RoleDto>>> HandleAsync(ListRolesQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var caller = query.Caller;

        if (caller.IsRoot)
        {
            return (await roles.ListAllAsync(cancellationToken).ConfigureAwait(false)).Select(role => role.ToDto()).ToList();
        }

        if (caller.EffectiveTenantId is not { } tenant)
        {
            return Error.Forbidden(ManagementErrors.NotYourTenant, "Your session acts in no tenant.");
        }

        if (await guard.RequireAsync(caller, tenant, guard.Options.Permissions.RolesRead, cancellationToken).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        return (await roles.ListAsync(tenant, cancellationToken).ConfigureAwait(false)).Select(role => role.ToDto()).ToList();
    }
}

// ---- CreateRole --------------------------------------------------------------------------------------------------------

/// <summary>Creates a custom role in the caller's tenant (or a global role, Root only).</summary>
public sealed record CreateRoleCommand(ManagementCaller Caller, CreateRoleRequest Request);

public sealed class CreateRoleHandler(
    IRoleRepository roles,
    IUnitOfWork unitOfWork,
    ManagementGuard guard,
    HeldPermissions held,
    PermissionCatalog catalog,
    ManagementAudit audit,
    TimeProvider time) : ICommandHandler<CreateRoleCommand, RoleDto>
{
    public async Task<Result<RoleDto>> HandleAsync(CreateRoleCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var (caller, request) = command;

        if (string.IsNullOrWhiteSpace(request.Name))
        {
            return Error.Validation([new ValidationFailure(nameof(request.Name), "A name is required.")]);
        }

        Guid? tenant = null;
        if (request.Global)
        {
            if (!caller.IsRoot)
            {
                return Error.Forbidden(ManagementErrors.MissingPermission, "Only a platform administrator can create global roles.");
            }
        }
        else
        {
            tenant = caller.EffectiveTenantId;
            if (tenant is null)
            {
                return Error.Forbidden(ManagementErrors.NotYourTenant, "Your session acts in no tenant.");
            }

            if (await guard.RequireAsync(caller, tenant.Value, guard.Options.Permissions.RolesWrite, cancellationToken).ConfigureAwait(false) is { } refused)
            {
                return refused;
            }
        }

        var permissions = (request.Permissions ?? []).Select(Permission.Normalize).Distinct().ToList();
        if (await catalog.UnknownAsync(permissions, cancellationToken).ConfigureAwait(false) is { Count: > 0 } unknown)
        {
            return Error.Failure(ManagementErrors.UnknownPermission, $"Unknown permissions: {string.Join(", ", unknown)}.");
        }

        if (!caller.IsRoot)
        {
            var holds = await held.OfCallerAsync(caller, tenant!.Value, "tenant", null, cancellationToken).ConfigureAwait(false);
            if (AssignmentRules.Uncovered(holds, permissions) is { Count: > 0 } missing)
            {
                return Error.Forbidden(ManagementErrors.Escalation, $"A role can't carry permissions you don't hold: {string.Join(", ", missing.Take(5))}.");
            }
        }

        var role = Role.Create(request.Name, tenant, time.GetUtcNow(), minScopeKey: request.MinScopeKey, complianceControls: request.ComplianceControls);
        foreach (var permission in permissions)
        {
            role.AddPermission(permission);
        }

        roles.Add(role);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync("role.created", "role", role.Id.ToString(), caller, tenant, cancellationToken).ConfigureAwait(false);
        return role.ToDto();
    }
}

// ---- ChangeRolePermission ----------------------------------------------------------------------------------------------

/// <summary>Adds or removes one permission of a role; queued for a second approver when four-eyes applies.</summary>
public sealed record ChangeRolePermissionCommand(ManagementCaller Caller, Guid RoleId, string Permission, bool Add);

public sealed class ChangeRolePermissionHandler(
    IRoleRepository roles,
    IRoleChangeRepository changes,
    IUnitOfWork unitOfWork,
    ManagementGuard guard,
    HeldPermissions held,
    PermissionCatalog catalog,
    RoleChangeApplier applier,
    ManagementAudit audit,
    TimeProvider time) : ICommandHandler<ChangeRolePermissionCommand, ChangeOutcomeDto>
{
    public async Task<Result<ChangeOutcomeDto>> HandleAsync(ChangeRolePermissionCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var caller = command.Caller;
        var code = Permission.Normalize(command.Permission);

        var role = await roles.FindAsync(command.RoleId, cancellationToken).ConfigureAwait(false);
        if (role is null)
        {
            return Error.NotFound(ManagementErrors.NotFound, "No such role.");
        }

        if (role.IsBuiltIn && !caller.IsRoot)
        {
            return Error.Forbidden(ManagementErrors.BuiltIn, "Built-in roles can't be changed.");
        }

        if (role.TenantId is null && !caller.IsRoot)
        {
            return Error.Forbidden(ManagementErrors.MissingPermission, "Only a platform administrator can change global roles.");
        }

        if (role.TenantId is { } tenant)
        {
            if (await guard.RequireAsync(caller, tenant, guard.Options.Permissions.RolesWrite, cancellationToken).ConfigureAwait(false) is { } refused)
            {
                return refused;
            }

            if (command.Add && !caller.IsRoot
                && AssignmentRules.Uncovered(await held.OfCallerAsync(caller, tenant, "tenant", null, cancellationToken).ConfigureAwait(false), [code]).Count > 0)
            {
                return Error.Forbidden(ManagementErrors.Escalation, $"You can't add {code}: you don't hold it.");
            }
        }

        if (command.Add && await catalog.UnknownAsync([code], cancellationToken).ConfigureAwait(false) is { Count: > 0 })
        {
            return Error.Failure(ManagementErrors.UnknownPermission, $"Unknown permission: {code}.");
        }

        var kind = command.Add ? RoleChangeKind.AddPermission : RoleChangeKind.RemovePermission;
        var request = RoleChangeRequest.PermissionChange(kind, role.Id, code, role.TenantId, caller.UserId ?? Guid.Empty, time.GetUtcNow());

        if (!caller.IsRoot && await guard.ApprovalRequiredAsync(role.TenantId, cancellationToken).ConfigureAwait(false))
        {
            changes.Add(request);
            await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            await audit.WriteAsync("role.change.requested", "role", role.Id.ToString(), caller, role.TenantId, cancellationToken).ConfigureAwait(false);
            return new ChangeOutcomeDto(Applied: false, request.Id);
        }

        if (await applier.ApplyAsync(request, caller.UserId ?? Guid.Empty, cancellationToken).ConfigureAwait(false) is { } failed)
        {
            return failed;
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync(command.Add ? "role.permission.added" : "role.permission.removed", "role", role.Id.ToString(), caller, role.TenantId, cancellationToken,
            details: new Dictionary<string, string?> { ["permission"] = code }).ConfigureAwait(false);
        return new ChangeOutcomeDto(Applied: true, null);
    }
}

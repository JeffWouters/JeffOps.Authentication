using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Application.Management;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Management;

namespace JeffOps.Authorization.Application.Features.Assignments;

// ---- AssignRole --------------------------------------------------------------------------------------------------------

/// <summary>
/// Assigns a role (docs/DESIGN.md §11.5). The caller must hold the assignment permission in the target tenant at the target
/// scope; to grant a privileged role, or any role to themselves, they must hold every permission it carries; a break-glass
/// role must be time-boxed and, unless Root grants it, waits for a second approver.
/// </summary>
public sealed record AssignRoleCommand(ManagementCaller Caller, AssignRoleRequest Request);

public sealed class AssignRoleHandler(
    IRoleRepository roles,
    IAssignmentRepository assignments,
    IRoleChangeRepository changes,
    IUnitOfWork unitOfWork,
    ManagementGuard guard,
    HeldPermissions held,
    RoleChangeApplier applier,
    ManagementAudit audit,
    TimeProvider time) : ICommandHandler<AssignRoleCommand, ChangeOutcomeDto>
{
    public async Task<Result<ChangeOutcomeDto>> HandleAsync(AssignRoleCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var (caller, request) = command;
        var scopeKey = Scope.Normalize(request.ScopeKey);
        var now = time.GetUtcNow();

        var role = await roles.FindAsync(request.RoleId, cancellationToken).ConfigureAwait(false);
        if (role is null || (role.TenantId is { } owner && owner != request.TenantId))
        {
            return Error.NotFound(ManagementErrors.NotFound, "No such role in this tenant.");
        }

        if (await guard.RequireAsync(caller, request.TenantId, guard.Options.Permissions.AssignmentsWrite, cancellationToken, scopeKey, request.ScopeInstanceId).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        if (!AssignmentRules.ScopeAllowed(role, scopeKey, await held.TreeAsync(cancellationToken).ConfigureAwait(false)))
        {
            return Error.Failure(ManagementErrors.InvalidScope, role.MinScopeKey is null
                ? $"Unknown scope '{scopeKey}'."
                : $"'{role.Name}' can only be assigned at '{role.MinScopeKey}' or broader.");
        }

        if (AssignmentRules.ExpiryProblem(role, request.ExpiresAt, now, guard.Options.BreakGlassMaxDuration) is { } expiryProblem)
        {
            return Error.Failure(ManagementErrors.InvalidExpiry, expiryProblem);
        }

        if (!caller.IsRoot)
        {
            var holds = await held.OfCallerAsync(caller, request.TenantId, scopeKey, request.ScopeInstanceId, cancellationToken).ConfigureAwait(false);
            var missing = AssignmentRules.CeilingViolations(role, holds, grantingToSelf: caller.UserId == request.UserId, guard.Options.PrivilegedPermissions());
            if (missing.Count > 0)
            {
                return Error.Forbidden(ManagementErrors.Escalation, $"You can't grant '{role.Name}': it carries permissions you don't hold ({string.Join(", ", missing.Take(5))}).");
            }
        }

        var existing = await assignments.ListForUserAsync(request.UserId, request.TenantId, cancellationToken).ConfigureAwait(false);
        if (existing.Any(assignment => assignment.RoleId == role.Id && assignment.ScopeKey == scopeKey && assignment.ScopeInstanceId == request.ScopeInstanceId && !assignment.IsExpired(now)))
        {
            return Error.Conflict(ManagementErrors.Duplicate, "The user already has this role at this scope.");
        }

        if (role.IsBreakGlass && !caller.IsRoot)
        {
            var pending = RoleChangeRequest.AssignBreakGlass(role.Id, request.UserId, request.TenantId, scopeKey, request.ScopeInstanceId, request.ExpiresAt!.Value, caller.UserId!.Value, now);
            changes.Add(pending);
            await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            await audit.WriteAsync("assignment.breakglass.requested", "role", role.Id.ToString(), caller, request.TenantId, cancellationToken, AuditSeverity.Warning).ConfigureAwait(false);
            return new ChangeOutcomeDto(Applied: false, pending.Id);
        }

        var grant = Assignment.Grant(request.UserId, role.Id, request.TenantId, scopeKey, request.ScopeInstanceId, request.ExpiresAt, caller.UserId, now);
        assignments.Add(grant);
        if (role.IsBreakGlass)
        {
            grant.AnnouncePrivileged(role.Name, await applier.WatchersAsync(request.TenantId, cancellationToken).ConfigureAwait(false));
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync("assignment.granted", "assignment", grant.Id.ToString(), caller, request.TenantId, cancellationToken,
            role.IsBreakGlass ? AuditSeverity.Warning : AuditSeverity.Information,
            new Dictionary<string, string?> { ["user"] = request.UserId.ToString(), ["role"] = role.Name, ["scope"] = scopeKey }).ConfigureAwait(false);
        return new ChangeOutcomeDto(Applied: true, grant.Id);
    }
}

// ---- RevokeAssignment --------------------------------------------------------------------------------------------------

public sealed record RevokeAssignmentCommand(ManagementCaller Caller, Guid AssignmentId);

public sealed class RevokeAssignmentHandler(
    IAssignmentRepository assignments,
    IRoleRepository roles,
    IUnitOfWork unitOfWork,
    ManagementGuard guard,
    HeldPermissions held,
    ManagementAudit audit) : ICommandHandler<RevokeAssignmentCommand>
{
    public async Task<Result> HandleAsync(RevokeAssignmentCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var caller = command.Caller;

        var assignment = await assignments.FindAsync(command.AssignmentId, cancellationToken).ConfigureAwait(false);
        if (assignment is null || !caller.MayActIn(assignment.TenantId))
        {
            return Error.NotFound(ManagementErrors.NotFound, "No such assignment.");
        }

        if (await guard.RequireAsync(caller, assignment.TenantId, guard.Options.Permissions.AssignmentsWrite, cancellationToken).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        // Revoking someone else's privileged role needs the same ceiling as granting it; revoking your own never does.
        if (!caller.IsRoot && caller.UserId != assignment.UserId
            && await roles.FindAsync(assignment.RoleId, cancellationToken).ConfigureAwait(false) is { } role
            && AssignmentRules.IsPrivileged(role, guard.Options.PrivilegedPermissions()))
        {
            var holds = await held.OfCallerAsync(caller, assignment.TenantId, "tenant", null, cancellationToken).ConfigureAwait(false);
            if (AssignmentRules.Uncovered(holds, role.PermissionCodes()).Count > 0)
            {
                return Error.Forbidden(ManagementErrors.Escalation, $"You can't revoke '{role.Name}': it carries permissions you don't hold.");
            }
        }

        assignment.Revoke();
        assignments.Remove(assignment);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync("assignment.revoked", "assignment", assignment.Id.ToString(), caller, assignment.TenantId, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

// ---- ListTenantAssignments ---------------------------------------------------------------------------------------------

/// <summary>Every assignment in a tenant: the access review.</summary>
public sealed record ListTenantAssignmentsQuery(ManagementCaller Caller, Guid TenantId);

public sealed class ListTenantAssignmentsHandler(IAssignmentRepository assignments, IRoleRepository roles, ManagementGuard guard)
    : IQueryHandler<ListTenantAssignmentsQuery, IReadOnlyList<AssignmentDto>>
{
    public async Task<Result<IReadOnlyList<AssignmentDto>>> HandleAsync(ListTenantAssignmentsQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        if (await guard.RequireAsync(query.Caller, query.TenantId, guard.Options.Permissions.AssignmentsRead, cancellationToken).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        var names = (await roles.ListAsync(query.TenantId, cancellationToken).ConfigureAwait(false)).ToDictionary(role => role.Id, role => role.Name);
        return (await assignments.ListForTenantAsync(query.TenantId, cancellationToken).ConfigureAwait(false))
            .Select(assignment => new AssignmentDto(
                assignment.Id, assignment.UserId, assignment.RoleId, names.GetValueOrDefault(assignment.RoleId, "?"),
                assignment.TenantId, assignment.ScopeKey, assignment.ScopeInstanceId, assignment.ExpiresAt))
            .ToList();
    }
}

// ---- RecertifyAssignment -----------------------------------------------------------------------------------------------

/// <summary>Extends a time-boxed assignment after review. Nobody recertifies their own access.</summary>
public sealed record RecertifyAssignmentCommand(ManagementCaller Caller, Guid AssignmentId, DateTimeOffset ExpiresAt);

public sealed class RecertifyAssignmentHandler(
    IAssignmentRepository assignments,
    IRoleRepository roles,
    IUnitOfWork unitOfWork,
    ManagementGuard guard,
    HeldPermissions held,
    ManagementAudit audit,
    TimeProvider time) : ICommandHandler<RecertifyAssignmentCommand>
{
    public async Task<Result> HandleAsync(RecertifyAssignmentCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        var caller = command.Caller;

        var assignment = await assignments.FindAsync(command.AssignmentId, cancellationToken).ConfigureAwait(false);
        if (assignment is null || !caller.MayActIn(assignment.TenantId))
        {
            return Error.NotFound(ManagementErrors.NotFound, "No such assignment.");
        }

        if (!caller.IsRoot && caller.UserId == assignment.UserId)
        {
            return Error.Forbidden(ManagementErrors.SelfRecertification, "You can't recertify your own access; another administrator has to review it.");
        }

        if (await guard.RequireAsync(caller, assignment.TenantId, guard.Options.Permissions.AssignmentsWrite, cancellationToken, assignment.ScopeKey, assignment.ScopeInstanceId).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        if (AssignmentRules.RecertifyProblem(command.ExpiresAt, time.GetUtcNow(), guard.Options.MaxRecertifyExtension) is { } problem)
        {
            return Error.Failure(ManagementErrors.InvalidExpiry, problem);
        }

        var role = await roles.FindAsync(assignment.RoleId, cancellationToken).ConfigureAwait(false);
        if (role is not null)
        {
            if (role.IsBreakGlass && command.ExpiresAt - time.GetUtcNow() > guard.Options.BreakGlassMaxDuration)
            {
                return Error.Failure(ManagementErrors.InvalidExpiry, $"'{role.Name}' can be extended by at most {guard.Options.BreakGlassMaxDuration}.");
            }

            if (!caller.IsRoot)
            {
                var holds = await held.OfCallerAsync(caller, assignment.TenantId, assignment.ScopeKey, assignment.ScopeInstanceId, cancellationToken).ConfigureAwait(false);
                if (AssignmentRules.CeilingViolations(role, holds, grantingToSelf: false, guard.Options.PrivilegedPermissions()).Count > 0)
                {
                    return Error.Forbidden(ManagementErrors.Escalation, $"You can't recertify '{role.Name}': it carries permissions you don't hold.");
                }
            }
        }

        assignment.Recertify(command.ExpiresAt);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync("assignment.recertified", "assignment", assignment.Id.ToString(), caller, assignment.TenantId, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

// ---- SweepExpiredAssignments -------------------------------------------------------------------------------------------

/// <summary>Deletes expired assignments, announcing each revocation. Run on a schedule; decisions already ignore them.</summary>
public sealed record SweepExpiredAssignmentsCommand;

public sealed class SweepExpiredAssignmentsHandler(IAssignmentRepository assignments, IUnitOfWork unitOfWork, TimeProvider time)
    : ICommandHandler<SweepExpiredAssignmentsCommand, int>
{
    public async Task<Result<int>> HandleAsync(SweepExpiredAssignmentsCommand command, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow();
        var expired = (await assignments.ListExpiringAsync(cancellationToken).ConfigureAwait(false)).Where(assignment => assignment.IsExpired(now)).ToList();
        foreach (var assignment in expired)
        {
            assignment.Revoke();
            assignments.Remove(assignment);
        }

        if (expired.Count > 0)
        {
            await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }

        return expired.Count;
    }
}

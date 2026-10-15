using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authorization.Application.Abstractions;
using JeffOps.Authorization.Application.Management;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Ceilings;
using JeffOps.Authorization.Domain.Decisions;
using JeffOps.Authorization.Domain.Management;
using JeffOps.Authorization.Domain.Policies;

namespace JeffOps.Authorization.Application.Features.Policies;

/// <summary>
/// ABAC policies are platform-wide, so only platform administrators (Root) change them; a Deny policy fences everyone,
/// including other tenants (docs/DESIGN.md §11.1).
/// </summary>
internal static class PolicyRules
{
    public static Error? RequireRoot(ManagementCaller caller) =>
        caller.IsRoot ? null : Error.Forbidden(ManagementErrors.MissingPermission, "Only a platform administrator can manage attribute policies.");

    public static AttributePolicyDto ToDto(this StoredPolicy policy) => new(
        policy.Id, policy.Name, policy.Description, policy.TargetAction, policy.TargetResourceType, policy.Effect, policy.ConditionJson, policy.Priority, policy.Enabled);
}

public sealed record ListPoliciesQuery(ManagementCaller Caller);

public sealed class ListPoliciesHandler(IPolicyRepository policies) : IQueryHandler<ListPoliciesQuery, IReadOnlyList<AttributePolicyDto>>
{
    public async Task<Result<IReadOnlyList<AttributePolicyDto>>> HandleAsync(ListPoliciesQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        if (PolicyRules.RequireRoot(query.Caller) is { } refused)
        {
            return refused;
        }

        return (await policies.ListAsync(cancellationToken).ConfigureAwait(false)).OrderByDescending(policy => policy.Priority).Select(policy => policy.ToDto()).ToList();
    }
}

/// <summary>Creates a policy, or updates it when <see cref="PolicyId"/> is given. The condition is validated.</summary>
public sealed record UpsertPolicyCommand(ManagementCaller Caller, Guid? PolicyId, UpsertPolicyRequest Request);

public sealed class UpsertPolicyHandler(IPolicyRepository policies, IUnitOfWork unitOfWork, ManagementAudit audit, TimeProvider time)
    : ICommandHandler<UpsertPolicyCommand, AttributePolicyDto>
{
    public async Task<Result<AttributePolicyDto>> HandleAsync(UpsertPolicyCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (PolicyRules.RequireRoot(command.Caller) is { } refused)
        {
            return refused;
        }

        var request = command.Request;
        StoredPolicy policy;
        try
        {
            if (command.PolicyId is { } id)
            {
                policy = await policies.FindAsync(id, cancellationToken).ConfigureAwait(false)
                    ?? throw new KeyNotFoundException();
                policy.Update(request.Name, request.Description, request.TargetAction, request.TargetResourceType, request.Effect, request.ConditionJson, request.Priority, request.Enabled);
            }
            else
            {
                policy = StoredPolicy.Create(request.Name, request.Description, request.TargetAction, request.TargetResourceType, request.Effect, request.ConditionJson, request.Priority, request.Enabled, time.GetUtcNow());
                policies.Add(policy);
            }
        }
        catch (KeyNotFoundException)
        {
            return Error.NotFound(ManagementErrors.NotFound, "No such policy.");
        }
        catch (FormatException exception)
        {
            return Error.Failure(ManagementErrors.InvalidCondition, exception.Message);
        }
        catch (ArgumentException exception)
        {
            return Error.Validation([new ValidationFailure(exception.ParamName ?? "request", exception.Message)]);
        }

        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync("policy.saved", "policy", policy.Id.ToString(), command.Caller, null, cancellationToken,
            policy.Effect == PolicyEffect.Deny ? AuditSeverity.Warning : AuditSeverity.Information).ConfigureAwait(false);
        return policy.ToDto();
    }
}

public sealed record DeletePolicyCommand(ManagementCaller Caller, Guid PolicyId);

public sealed class DeletePolicyHandler(IPolicyRepository policies, IUnitOfWork unitOfWork, ManagementAudit audit) : ICommandHandler<DeletePolicyCommand>
{
    public async Task<Result> HandleAsync(DeletePolicyCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (PolicyRules.RequireRoot(command.Caller) is { } refused)
        {
            return refused;
        }

        var policy = await policies.FindAsync(command.PolicyId, cancellationToken).ConfigureAwait(false);
        if (policy is null)
        {
            return Error.NotFound(ManagementErrors.NotFound, "No such policy.");
        }

        policy.Delete();
        policies.Remove(policy);
        await unitOfWork.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await audit.WriteAsync("policy.deleted", "policy", policy.Id.ToString(), command.Caller, null, cancellationToken).ConfigureAwait(false);
        return Result.Success();
    }
}

/// <summary>
/// Dry-runs a decision against the stored policies and stated facts, without changing anything. The per-policy trace is
/// returned only to platform administrators, since policies may reveal security posture.
/// </summary>
public sealed record SimulateDecisionQuery(ManagementCaller Caller, SimulateRequest Request);

public sealed class SimulateDecisionHandler(IPolicyRepository policies) : IQueryHandler<SimulateDecisionQuery, SimulateResponse>
{
    public async Task<Result<SimulateResponse>> HandleAsync(SimulateDecisionQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        var request = query.Request;

        var compiled = (await policies.ListAsync(cancellationToken).ConfigureAwait(false))
            .Select(policy => AttributePolicy.Compile(policy.Name, policy.Effect, policy.TargetAction, policy.TargetResourceType, policy.ConditionJson, policy.Priority, policy.Enabled))
            .ToList();

        var pipeline = new AuthorizationPipeline(StepUpPolicy.None, ImpersonationPolicy.None, DelegationCeiling.Default);
        var decision = pipeline.Evaluate(new AuthorizationFacts
        {
            Action = request.Action,
            ResourceType = request.ResourceType,
            Attributes = request.Attributes ?? new Dictionary<string, System.Text.Json.JsonElement>(),
            HasRoleGrant = request.HasRoleGrant,
            IsRoot = request.IsRoot,
            Policies = compiled,
        });

        var trace = query.Caller.IsRoot ? decision.Trace.Select(item => new PolicyTraceDto(item.PolicyName, item.Effect, item.Matched)).ToList() : [];
        return new SimulateResponse(decision.Allowed, decision.Code, decision.Reason, trace);
    }
}

using System.Text.Json;

namespace JeffOps.Authorization.Domain.Policies;

public enum PolicyEffect
{
    Permit = 0,
    Deny = 1,
}

/// <summary>Per-policy outcome of a decision, for explaining it.</summary>
public sealed record PolicyTrace(string PolicyName, PolicyEffect Effect, bool Matched);

/// <summary>
/// A compiled ABAC policy. Applies to a request when it is enabled, its target action is the requested action or
/// <c>*</c>, and its target resource type (if any) is the request's resource type; then, when its condition holds, its
/// <see cref="Effect"/> counts.
/// </summary>
public sealed class AttributePolicy
{
    private AttributePolicy(
        string name,
        PolicyEffect effect,
        string targetAction,
        string? targetResourceType,
        Condition condition,
        int priority,
        bool enabled,
        string? compileError)
    {
        Name = name;
        Effect = effect;
        TargetAction = targetAction;
        TargetResourceType = string.IsNullOrWhiteSpace(targetResourceType) ? null : targetResourceType.Trim();
        Condition = condition;
        Priority = priority;
        Enabled = enabled;
        CompileError = compileError;
    }

    public string Name { get; }

    public PolicyEffect Effect { get; }

    public string TargetAction { get; }

    /// <summary>The resource type the policy is limited to; null or <c>*</c> means any (docs/DESIGN.md §17, I1).</summary>
    public string? TargetResourceType { get; }

    public Condition Condition { get; }

    public int Priority { get; }

    public bool Enabled { get; }

    /// <summary>Why the stored condition could not be compiled, or null when it compiled.</summary>
    public string? CompileError { get; }

    /// <summary>
    /// Compiles a stored policy. A condition that fails to compile fails CLOSED: a Deny policy then always matches and a
    /// Permit policy never does, so a broken policy can only take access away. Management validates conditions on write,
    /// so this guards against data written by older versions or by hand.
    /// </summary>
    public static AttributePolicy Compile(
        string name,
        PolicyEffect effect,
        string targetAction,
        string? targetResourceType,
        string? conditionJson,
        int priority,
        bool enabled)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(targetAction);

        return ConditionParser.TryParse(conditionJson, out var condition, out var error)
            ? new AttributePolicy(name, effect, targetAction.Trim(), targetResourceType, condition, priority, enabled, null)
            : new AttributePolicy(
                name,
                effect,
                targetAction.Trim(),
                targetResourceType,
                effect == PolicyEffect.Deny ? Condition.Always : Condition.Never,
                priority,
                enabled,
                error);
    }

    public bool AppliesTo(string action, string? resourceType) =>
        Enabled
        && (TargetAction == "*" || string.Equals(TargetAction, action, StringComparison.OrdinalIgnoreCase))
        && (TargetResourceType is null or "*" || string.Equals(TargetResourceType, resourceType, StringComparison.OrdinalIgnoreCase));

    public bool Matches(IReadOnlyDictionary<string, JsonElement> context) => Condition.Evaluate(context);
}

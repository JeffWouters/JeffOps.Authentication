using JeffOps.Authentication.SharedKernel.Domain;
using JeffOps.Authorization.Domain.Policies;

namespace JeffOps.Authorization.Domain.Management;

/// <summary>An ABAC policy as stored and managed. Its condition is validated on every write.</summary>
public sealed class StoredPolicy : AggregateRoot<Guid>
{
    private StoredPolicy(Guid id)
        : base(id)
    {
    }

    private StoredPolicy()
    {
    }

    public string Name { get; private set; } = string.Empty;

    public string? Description { get; private set; }

    public string TargetAction { get; private set; } = "*";

    public string? TargetResourceType { get; private set; }

    public PolicyEffect Effect { get; private set; }

    public string ConditionJson { get; private set; } = "{}";

    public int Priority { get; private set; }

    public bool Enabled { get; private set; }

    /// <summary>Creates a policy.</summary>
    /// <exception cref="FormatException">The condition is not valid.</exception>
    public static StoredPolicy Create(string name, string? description, string targetAction, string? targetResourceType, PolicyEffect effect, string conditionJson, int priority, bool enabled, DateTimeOffset now)
    {
        var policy = new StoredPolicy(Guid.CreateVersion7(now));
        policy.Update(name, description, targetAction, targetResourceType, effect, conditionJson, priority, enabled);
        return policy;
    }

    /// <summary>Updates the policy.</summary>
    /// <exception cref="FormatException">The condition is not valid.</exception>
    public void Update(string name, string? description, string targetAction, string? targetResourceType, PolicyEffect effect, string conditionJson, int priority, bool enabled)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetAction);
        if (!Policies.AttributePolicy.IsValidTarget(targetAction))
        {
            throw new ArgumentException("A policy targets *, one action, or a prefix such as billing.*.", nameof(targetAction));
        }

        ConditionParser.Parse(conditionJson);

        Name = name.Trim();
        Description = string.IsNullOrWhiteSpace(description) ? null : description.Trim();
        TargetAction = targetAction.Trim().ToLowerInvariant();
        TargetResourceType = string.IsNullOrWhiteSpace(targetResourceType) ? null : targetResourceType.Trim();
        Effect = effect;
        ConditionJson = string.IsNullOrWhiteSpace(conditionJson) ? "{}" : conditionJson;
        Priority = priority;
        Enabled = enabled;
        Raise(new PolicyChanged(Id));
    }

    public void Delete() => Raise(new PolicyChanged(Id));
}

public sealed record PolicyChanged(Guid PolicyId) : IDomainEvent;

/// <summary>A node of the scope hierarchy. The root (<c>system</c>) and seeded scopes are built in.</summary>
public sealed class Scope : AggregateRoot<string>
{
    private Scope(string key, string name, string? description, string? parentKey, bool isBuiltIn)
        : base(key)
    {
        Name = name;
        Description = description;
        ParentKey = parentKey;
        IsBuiltIn = isBuiltIn;
    }

    private Scope()
    {
    }

    public string Name { get; private set; } = string.Empty;

    public string? Description { get; private set; }

    public string? ParentKey { get; private set; }

    public bool IsBuiltIn { get; private set; }

    public static Scope Create(string key, string name, string? description, string? parentKey, bool isBuiltIn = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var scope = new Scope(Normalize(key), name.Trim(), description, parentKey is null ? null : Normalize(parentKey), isBuiltIn);
        scope.Raise(new ScopesChanged());
        return scope;
    }

    public void Update(string name, string? description, string? parentKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        Name = name.Trim();
        Description = description;
        ParentKey = parentKey is null ? null : Normalize(parentKey);
        Raise(new ScopesChanged());
    }

    public void Delete() => Raise(new ScopesChanged());

    public static string Normalize(string key) => key.Trim().ToLowerInvariant();
}

public sealed record ScopesChanged : IDomainEvent;

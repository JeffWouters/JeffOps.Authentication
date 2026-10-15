using System.Text.Json;
using JeffOps.Authorization.Domain.Decisions;

namespace JeffOps.Authorization.AspNetCore.Evaluation;

/// <summary>
/// An authorization question for the current caller.
/// </summary>
/// <param name="Action">The permission code, e.g. <c>billing.invoice.read</c>.</param>
public sealed record AuthorizationRequest(string Action)
{
    /// <summary>The type of the resource, matched against policies limited to a resource type.</summary>
    public string? ResourceType { get; init; }

    /// <summary>Resource attributes, exposed to policies as <c>resource.*</c>. Build with <see cref="AuthorizationAttributes.Resource"/>.</summary>
    public IReadOnlyDictionary<string, JsonElement>? Resource { get; init; }

    /// <summary>The scope the request targets; defaults to <see cref="PermissionAuthorizationOptions.DefaultScopeKey"/>.</summary>
    public string? ScopeKey { get; init; }

    /// <summary>The scope instance targeted; an instance-bound role assignment grants only when it matches.</summary>
    public Guid? ScopeInstanceId { get; init; }
}

/// <summary>
/// Imperative authorization for code paths that can't be decided by an endpoint policy alone, for example after loading
/// the resource whose attributes a policy needs.
/// </summary>
public interface IAuthorizer
{
    /// <summary>The full decision (RBAC, ABAC, ceilings, impersonation, step-up) for the current caller.</summary>
    Task<AuthorizationDecision> AuthorizeAsync(AuthorizationRequest request, CancellationToken cancellationToken = default);

    /// <summary>Whether the current caller may perform <paramref name="permission"/> at the default scope.</summary>
    Task<bool> HasPermissionAsync(string permission, CancellationToken cancellationToken = default);
}

/// <summary>Builds <c>resource.*</c> attribute bags.</summary>
public static class AuthorizationAttributes
{
    /// <summary>Serializes the public properties of <paramref name="values"/> (e.g. <c>new { tenantId, amount }</c>).</summary>
    public static IReadOnlyDictionary<string, JsonElement> Resource(object values)
    {
        ArgumentNullException.ThrowIfNull(values);

        var element = JsonSerializer.SerializeToElement(values);
        return element.ValueKind == JsonValueKind.Object
            ? element.EnumerateObject().ToDictionary(property => property.Name, property => property.Value.Clone(), StringComparer.Ordinal)
            : throw new ArgumentException("Resource attributes must serialize to a JSON object.", nameof(values));
    }
}

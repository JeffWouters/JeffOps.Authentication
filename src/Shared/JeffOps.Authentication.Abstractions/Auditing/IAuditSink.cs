namespace JeffOps.Authentication.Abstractions.Auditing;

public enum AuditSeverity
{
    Information,
    Warning,
}

/// <summary>
/// A security-relevant action, recorded for the host's audit trail.
/// </summary>
/// <param name="Action">Stable action name, for example <c>pat.created</c> or <c>account.disabled</c>.</param>
/// <param name="TargetType">The kind of thing acted on, for example <c>pat</c> or <c>account</c>.</param>
/// <param name="TargetId">Its id.</param>
public sealed record AuditRecord(string Action, string TargetType, string TargetId)
{
    /// <summary>The account that acted; null for the system or an anonymous caller.</summary>
    public Guid? ActorId { get; init; }

    /// <summary>The tenant acted in, if any.</summary>
    public Guid? TenantId { get; init; }

    public AuditSeverity Severity { get; init; } = AuditSeverity.Information;

    public DateTimeOffset OccurredAt { get; init; }

    /// <summary>Extra, non-secret details.</summary>
    public IReadOnlyDictionary<string, string?> Details { get; init; } = new Dictionary<string, string?>();
}

/// <summary>
/// Where audit records go (docs/DESIGN.md §13). The default writes them to the log; a host forwards them to its audit store.
/// Implementations must not throw for a delivery failure they can retry themselves.
/// </summary>
public interface IAuditSink
{
    Task WriteAsync(AuditRecord record, CancellationToken cancellationToken);
}

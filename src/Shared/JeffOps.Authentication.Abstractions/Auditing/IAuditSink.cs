namespace JeffOps.Authentication.Abstractions.Auditing;

/// <summary>How much attention an <see cref="AuditRecord"/> deserves; the default sink logs warnings at a higher level.</summary>
public enum AuditSeverity
{
    /// <summary>A routine security-relevant action, for example creating or revoking an ordinary personal access token.</summary>
    Information,
    /// <summary>An action that deserves review, for example an operator disabling an account or a token allowed sensitive actions.</summary>
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

    /// <summary>How much attention the record deserves; <see cref="AuditSeverity.Information"/> by default.</summary>
    public AuditSeverity Severity { get; init; } = AuditSeverity.Information;

    /// <summary>When the action happened; set by the writer from its <see cref="TimeProvider"/>.</summary>
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
    /// <summary>Adds <paramref name="record"/> to the host's audit trail.</summary>
    Task WriteAsync(AuditRecord record, CancellationToken cancellationToken);
}

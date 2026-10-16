namespace JeffOps.Authentication.Abstractions.Notifications;

/// <summary>How urgently a <see cref="UserNotification"/> should reach its user; hosts can pick a channel by it.</summary>
public enum NotificationPriority
{
    /// <summary>Informational; any channel will do.</summary>
    Normal,
    /// <summary>Needs the user's attention soon, for example a request to impersonate them.</summary>
    High,
    /// <summary>Needs the user's attention now, for example a break-glass impersonation that started without their consent.</summary>
    Urgent,
}

/// <summary>A message for a user about their own account, for example "support asks to act as you".</summary>
/// <param name="UserId">Who is told.</param>
/// <param name="Kind">Stable kind, for example <c>impersonation.requested</c>, so hosts can choose a template or channel.</param>
/// <param name="Title">Short text.</param>
/// <param name="Message">Full text.</param>
public sealed record UserNotification(Guid UserId, string Kind, string Title, string Message)
{
    /// <summary>How urgent the notification is; <see cref="NotificationPriority.Normal"/> by default.</summary>
    public NotificationPriority Priority { get; init; } = NotificationPriority.Normal;

    /// <summary>What the notification is about, for example a grant id, so the host can link to it.</summary>
    public string? ReferenceId { get; init; }
}

/// <summary>
/// Delivers user notifications (in-app, email, push) — docs/DESIGN.md §13. The default writes them to the log; a host that
/// offers delegation should plug in a channel users actually see.
/// </summary>
public interface INotifier
{
    /// <summary>Delivers <paramref name="notification"/> to its user.</summary>
    Task NotifyAsync(UserNotification notification, CancellationToken cancellationToken);
}

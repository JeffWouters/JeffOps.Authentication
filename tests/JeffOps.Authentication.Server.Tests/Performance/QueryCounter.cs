using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace JeffOps.Authentication.Server.Tests.Performance;

/// <summary>
/// Counts the database commands every DbContext in the process executes (EF Core's diagnostic events), with their SQL, so a
/// probe can tell how many round trips one request costs. Process-wide: run probes alone, not beside other tests.
/// </summary>
internal sealed class QueryCounter : IObserver<DiagnosticListener>, IObserver<KeyValuePair<string, object?>>, IDisposable
{
    private readonly IDisposable _subscription;
    private readonly ConcurrentQueue<(string Context, string Sql)> _commands = new();
    private readonly List<IDisposable> _listeners = [];

    public QueryCounter() => _subscription = DiagnosticListener.AllListeners.Subscribe(this);

    public IReadOnlyList<(string Context, string Sql)> Commands => [.. _commands];

    public void Reset() => _commands.Clear();

    public void OnNext(DiagnosticListener value)
    {
        if (value.Name == DbLoggerCategory.Name)
        {
            lock (_listeners)
            {
                _listeners.Add(value.Subscribe(this));
            }
        }
    }

    public void OnNext(KeyValuePair<string, object?> value)
    {
        if (value.Key == RelationalEventId.CommandExecuted.Name && value.Value is CommandExecutedEventData executed)
        {
            _commands.Enqueue((executed.Context?.GetType().Name ?? "?", executed.Command.CommandText));
        }
        else if (value.Key == RelationalEventId.CommandError.Name && value.Value is CommandErrorEventData failed)
        {
            _commands.Enqueue((failed.Context?.GetType().Name ?? "?", "(failed) " + failed.Command.CommandText));
        }
    }

    public void OnCompleted()
    {
    }

    public void OnError(Exception error)
    {
    }

    public void Dispose()
    {
        _subscription.Dispose();
        lock (_listeners)
        {
            _listeners.ForEach(listener => listener.Dispose());
        }
    }
}

using Microsoft.Data.SqlClient;
using Microsoft.Data.Sqlite;

namespace JeffOps.Authentication.Tests.Shared;

/// <summary>
/// The database integration tests run against: SQLite files by default (fast, no setup), or SQL Server with
/// <c>JEFFOPS_TEST_DATABASE=SqlServer</c> — the production provider, migrated by the persistence packages' own
/// <c>migrateOnStartup</c> path. The server is <c>JEFFOPS_TEST_SQLSERVER</c> (a connection string without a database), by
/// default SQL Server LocalDB. Each test host gets its own database, dropped afterwards.
/// </summary>
internal static class TestDatabase
{
    private const string LocalDb = @"Server=(localdb)\MSSQLLocalDB;Integrated Security=true;TrustServerCertificate=true";

    /// <summary>Whether the tests run against SQL Server.</summary>
    public static bool SqlServer { get; } =
        string.Equals(Environment.GetEnvironmentVariable("JEFFOPS_TEST_DATABASE"), "SqlServer", StringComparison.OrdinalIgnoreCase);

    /// <summary>A fresh SQLite file for one module of one host (each DbContext opens its own connection, as in production).</summary>
    public static string SqliteFile(string name) =>
        new SqliteConnectionStringBuilder
        {
            DataSource = Path.Combine(Path.GetTempPath(), $"jeffops-{name}-{Guid.NewGuid():N}.db"),
            Pooling = false,
        }.ToString();

    /// <summary>Creates an empty SQL Server database (migrations add the schemas) and returns its connection string.</summary>
    public static async Task<string> CreateSqlServerAsync(string name, CancellationToken cancellationToken)
    {
        var server = new SqlConnectionStringBuilder(Environment.GetEnvironmentVariable("JEFFOPS_TEST_SQLSERVER") ?? LocalDb);
        var database = $"jeffops_{name}_{Guid.NewGuid():N}";

        await using (var connection = new SqlConnection(server.ConnectionString))
        {
            await connection.OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = $"CREATE DATABASE [{database}]";
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        server.InitialCatalog = database;
        return server.ConnectionString;
    }

    /// <summary>Deletes a SQLite database file and its WAL files, if there are any. Best effort.</summary>
    public static void DeleteSqlite(string connectionString)
    {
        SqliteConnection.ClearAllPools();
        var file = new SqliteConnectionStringBuilder(connectionString).DataSource;
        foreach (var path in new[] { file, file + "-wal", file + "-shm" })
        {
            try
            {
                File.Delete(path);
            }
            catch (IOException)
            {
                // Best effort.
            }
        }
    }

    /// <summary>Drops a test database: the SQL Server one, or the SQLite file. Best effort.</summary>
    public static async Task DeleteAsync(string connectionString)
    {
        if (!SqlServer)
        {
            DeleteSqlite(connectionString);
            return;
        }

        SqlConnection.ClearAllPools();
        var builder = new SqlConnectionStringBuilder(connectionString);
        var database = builder.InitialCatalog;
        builder.InitialCatalog = "master";
        try
        {
            await using var connection = new SqlConnection(builder.ConnectionString);
            await connection.OpenAsync();
            await using var command = connection.CreateCommand();
            command.CommandText = $"ALTER DATABASE [{database}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{database}]";
            await command.ExecuteNonQueryAsync();
        }
        catch (SqlException)
        {
            // Best effort: a leftover test database is harmless.
        }
    }
}

using Microsoft.Data.Sqlite;

namespace DotnetSecurityFailures.Services;

public class VulnerableDatabaseService : IDisposable
{
    private readonly SqliteConnection _connection;
    private bool _initialized = false;

    public VulnerableDatabaseService()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
    }

    public void EnsureInitialized()
    {
        if (_initialized) return;

        // Create Users table
        using var createTableCmd = _connection.CreateCommand();
        createTableCmd.CommandText = @"
            CREATE TABLE Users (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL,
                Email TEXT NOT NULL,
                Role TEXT NOT NULL,
                IsActive INTEGER NOT NULL DEFAULT 1
            )";
        createTableCmd.ExecuteNonQuery();

        // Create Secrets table for UNION injection demo
        using var createSecretsCmd = _connection.CreateCommand();
        createSecretsCmd.CommandText = @"
            CREATE TABLE Secrets (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                SecretKey TEXT NOT NULL,
                SecretValue TEXT NOT NULL
            )";
        createSecretsCmd.ExecuteNonQuery();

        // Insert sample users
        using var insertCmd = _connection.CreateCommand();
        insertCmd.CommandText = @"
            INSERT INTO Users (Username, Email, Role, IsActive) VALUES
            ('admin', 'admin@company.com', 'Administrator', 1),
            ('john_doe', 'john@company.com', 'User', 1),
            ('jane_smith', 'jane@company.com', 'Manager', 1),
            ('bob_wilson', 'bob@company.com', 'User', 1),
            ('service_account', 'service@company.com', 'System', 0)";
        insertCmd.ExecuteNonQuery();

        // Insert secrets
        using var insertSecretsCmd = _connection.CreateCommand();
        insertSecretsCmd.CommandText = @"
            INSERT INTO Secrets (SecretKey, SecretValue) VALUES
            ('API_KEY', 'sk-prod-abc123xyz789'),
            ('DB_PASSWORD', 'SuperSecret123!'),
            ('ENCRYPTION_KEY', 'aes256-key-very-secret'),
            ('ADMIN_TOKEN', 'admin-jwt-token-secret')";
        insertSecretsCmd.ExecuteNonQuery();

        _initialized = true;
    }

    // VULNERABLE: String concatenation - SQL Injection vulnerability
    public string SearchUserVulnerable(string username)
    {
        EnsureInitialized();

        try
        {
            // DANGEROUS: Direct string concatenation with additional WHERE condition
            var sql = $"SELECT * FROM Users WHERE Username = '{username}' AND IsActive = 1";
            
            using var command = _connection.CreateCommand();
            command.CommandText = sql;

            using var reader = command.ExecuteReader();
            
            if (!reader.HasRows)
            {
                return "User not found or inactive";
            }

            var results = new System.Text.StringBuilder();
            results.AppendLine("Query executed successfully!");
            results.AppendLine();

            int count = 0;
            while (reader.Read())
            {
                count++;
                results.AppendLine($"Record #{count}:");
                results.AppendLine($"  ID: {reader["Id"]}");
                results.AppendLine($"  Username: {reader["Username"]}");
                results.AppendLine($"  Email: {reader["Email"]}");
                results.AppendLine($"  Role: {reader["Role"]}");
                results.AppendLine($"  IsActive: {reader["IsActive"]}");
                results.AppendLine();
            }

            if (count > 1)
            {
                results.AppendLine($"WARNING: SQL Injection detected! Returned {count} records instead of 1!");
            }

            return results.ToString();
        }
        catch (SqliteException ex)
        {
            return $"SQL Error: {ex.Message}\n\nThis error message reveals database structure to attackers!";
        }
        catch (Exception ex)
        {
            return $"Error: {ex.Message}";
        }
    }


    public string GetExecutedQuery(string username)
    {
        return $"SELECT * FROM Users WHERE Username = '{username}' AND IsActive = 1";
    }

    public void Dispose()
    {
        _connection?.Dispose();
    }
}

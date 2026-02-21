using LiteDB;
using System.Text.Json;

namespace DotnetSecurityFailures.Services;

public class VulnerableNoSQLService : IDisposable
{
    private readonly LiteDatabase _database;
    private readonly ILiteCollection<BsonDocument> _usersCollection;

    public VulnerableNoSQLService()
    {
        // Create in-memory LiteDB database
        _database = new LiteDatabase(new MemoryStream());
        _usersCollection = _database.GetCollection("users");

        // Seed initial data
        SeedDatabase();
    }

    private void SeedDatabase()
    {
        _usersCollection.DeleteAll();

        var users = new[]
        {
            new BsonDocument
            {
                ["_id"] = ObjectId.NewObjectId(),
                ["username"] = "admin",
                ["password"] = "Admin123!",
                ["role"] = "Administrator"
            },
            new BsonDocument
            {
                ["_id"] = ObjectId.NewObjectId(),
                ["username"] = "user",
                ["password"] = "User123!",
                ["role"] = "User"
            },
            new BsonDocument
            {
                ["_id"] = ObjectId.NewObjectId(),
                ["username"] = "john.doe",
                ["password"] = "SecurePass2024",
                ["role"] = "User"
            }
        };

        foreach (var user in users)
        {
            _usersCollection.Insert(user);
        }
    }

    // VULNERABLE: String concatenation in query construction
    public BsonDocument? AuthenticateUserVulnerable(string username, string password)
    {
        try
        {
            // DANGEROUS: Building query by concatenating user input into JSON string
            // User input is NOT escaped, allowing injection of JSON operators
            var queryJson = $"{{ \"username\": {username}, \"password\": {password} }}";
            
            // Parse and deserialize - attackers can inject operators here!
            var jsonDoc = System.Text.Json.JsonSerializer.Deserialize<JsonDocument>(queryJson);
            if (jsonDoc == null) return null;

            // Convert to BsonDocument
            var filter = JsonToBsonDocument(jsonDoc.RootElement);
            
            // Now manually evaluate the filter against all users
            var allUsers = _usersCollection.FindAll();
            
            foreach (var user in allUsers)
            {
                if (MatchesFilter(user, filter))
                {
                    return user;
                }
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private BsonDocument JsonToBsonDocument(JsonElement element)
    {
        var doc = new BsonDocument();
        
        foreach (var property in element.EnumerateObject())
        {
            doc[property.Name] = JsonElementToBsonValue(property.Value);
        }
        
        return doc;
    }

    private BsonValue JsonElementToBsonValue(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.Object => JsonToBsonDocument(element),
            JsonValueKind.String => new BsonValue(element.GetString() ?? ""),
            JsonValueKind.Number => new BsonValue(element.GetDouble()),
            JsonValueKind.True => new BsonValue(true),
            JsonValueKind.False => new BsonValue(false),
            JsonValueKind.Null => BsonValue.Null,
            _ => new BsonValue(element.ToString())
        };
    }

    private bool MatchesFilter(BsonDocument user, BsonDocument filter)
    {
        foreach (var filterKey in filter.Keys)
        {
            if (!user.ContainsKey(filterKey))
            {
                return false;
            }

            var filterValue = filter[filterKey];
            var userValue = user[filterKey];

            // Check if filter value is an operator document
            if (filterValue.IsDocument)
            {
                var operatorDoc = filterValue.AsDocument;
                
                // Handle $ne (not equal) operator
                if (operatorDoc.ContainsKey("$ne"))
                {
                    var neValue = operatorDoc["$ne"].AsString;
                    if (userValue.AsString == neValue)
                    {
                        return false; // Does not match if equal
                    }
                }
                // Handle $regex operator
                else if (operatorDoc.ContainsKey("$regex"))
                {
                    var regexValue = operatorDoc["$regex"].AsString;
                    if (!System.Text.RegularExpressions.Regex.IsMatch(userValue.AsString, regexValue))
                    {
                        return false;
                    }
                }
                // Handle $gt (greater than) operator
                else if (operatorDoc.ContainsKey("$gt"))
                {
                    var gtValue = operatorDoc["$gt"].AsString;
                    if (string.Compare(userValue.AsString, gtValue, StringComparison.Ordinal) <= 0)
                    {
                        return false;
                    }
                }
            }
            else
            {
                // Normal equality check
                if (userValue.AsString != filterValue.AsString)
                {
                    return false;
                }
            }
        }

        return true; // All filter conditions matched
    }

    public string GetQueryRepresentation(string username, string password)
    {
        // Show how the query is constructed (without quotes around user input)
        return $"{{ \"username\": {username}, \"password\": {password} }}";
    }

    public void Dispose()
    {
        _database?.Dispose();
    }
}

namespace DotnetSecurityFailures.Services;

/// <summary>
/// VULNERABLE: Demonstrates LDAP injection vulnerability
/// DO NOT use this code in production!
/// </summary>
public class VulnerableLdapService
{
    private readonly List<LdapUser> _users;

    public VulnerableLdapService()
    {
        // Simulated LDAP directory data
        _users = new List<LdapUser>
        {
            new LdapUser
            {
                CN = "Administrator",
                OU = "Admins",
                DC = "company,DC=com",
                Email = "admin@company.com",
                Phone = "+1-555-0001",
                Groups = "Domain Admins, Enterprise Admins, Schema Admins",
                Description = "Full administrative access"
            },
            new LdapUser
            {
                CN = "John Doe",
                OU = "Users",
                DC = "company,DC=com",
                Email = "john.doe@company.com",
                Phone = "+1-555-0105",
                Department = "IT Security",
                SSN = "123-45-6789"
            },
            new LdapUser
            {
                CN = "Jane Smith",
                OU = "Users",
                DC = "company,DC=com",
                Email = "jane.smith@company.com",
                Department = "Engineering",
                Salary = "$85,000",
                Title = "Senior Engineer"
            },
            new LdapUser
            {
                CN = "ServiceAccount",
                OU = "Service",
                DC = "company,DC=com",
                Email = "service@company.com",
                Password = "P@ssw0rd123!",
                Permissions = "Database access, File share access"
            }
        };
    }

    /// <summary>
    /// VULNERABLE: String concatenation in LDAP filter
    /// This method is intentionally vulnerable for demonstration purposes
    /// </summary>
    public string SearchUserVulnerable(string username)
    {
        // DANGEROUS: Direct string concatenation in LDAP filter
        var filter = $"(&(objectClass=user)(cn={username}))";
        
        return EvaluateLdapFilter(filter, username);
    }

    public string GetExecutedQuery(string username)
    {
        return $"(&(objectClass=user)(cn={username}))";
    }

    private string EvaluateLdapFilter(string filter, string username)
    {
        var dangerousChars = new[] { "*", "(", ")", "&", "|" };
        var containsDangerous = dangerousChars.Any(c => username.Contains(c));

        // Wildcard attack
        if (username == "*")
        {
            var result = "LDAP INJECTION DETECTED!\n\n" +
                        "Wildcard character bypassed filter!\n\n" +
                        $"Original query: {filter}\n" +
                        "Result: Returns ALL users in directory!\n\n" +
                        "Exposed data:\n" +
                        "-----------------------------\n";

            foreach (var user in _users)
            {
                result += FormatUserDetails(user) + "\n";
            }

            result += $"\nTotal: {_users.Count} directory entries exposed!\n" +
                     "Complete directory compromise!";
            return result;
        }

        // Logic manipulation attack
        if (username.Contains(")(") || username.Contains("&(") || username.Contains("|("))
        {
            var result = "LDAP INJECTION DETECTED!\n\n" +
                        "Filter logic manipulation successful!\n\n" +
                        $"Injected query: {filter}\n\n" +
                        "What happened:\n";

            if (username.Contains("admin)(&(objectClass=*"))
            {
                result += "  Input: admin)(&(objectClass=*\n" +
                         "  Results in: (&(objectClass=user)(cn=admin)(&(objectClass=*))\n" +
                         "  Interpretation: Two conditions joined, bypassing original filter\n\n";
            }
            else if (username.Contains("*))(|(password=*"))
            {
                result += "  Input: *))(|(password=*\n" +
                         "  Results in: Query includes password extraction attempt\n" +
                         "  Interpretation: Attempts to extract password fields\n\n";
            }
            else
            {
                result += "  Input contains LDAP operators: )( or &( or |(\n" +
                         "  Results in: Filter logic manipulation\n\n";
            }

            result += "Attack variations demonstrated:\n" +
                     "  • Boolean logic injection with & and |\n" +
                     "  • Parentheses to close/open new conditions\n" +
                     "  • Always-true conditions to bypass authentication\n\n" +
                     "Exposed ALL directory objects:\n" +
                     "-----------------------------\n";

            foreach (var user in _users)
            {
                result += FormatUserDetails(user) + "\n";
            }

            result += $"\nTotal: {_users.Count} users exposed!\n" +
                     "Complete Active Directory exposure!";
            return result;
        }

        // Other dangerous characters
        if (containsDangerous)
        {
            var result = "LDAP INJECTION DETECTED!\n\n" +
                        "Special characters exploited the query!\n\n" +
                        $"Modified query: {filter}\n\n" +
                        "Returned ALL users from directory:\n\n";

            foreach (var user in _users)
            {
                result += FormatUserDetails(user) + "\n";
            }

            result += $"\nTotal: {_users.Count} users exposed!";
            return result;
        }

        // Normal search
        var foundUser = _users.FirstOrDefault(u => 
            u.CN.Equals(username, StringComparison.OrdinalIgnoreCase) ||
            u.CN.Replace(" ", ".").Equals(username, StringComparison.OrdinalIgnoreCase));

        if (foundUser != null)
        {
            return "User found:\n" + FormatUserDetails(foundUser);
        }

        return "User not found in directory";
    }

    private string FormatUserDetails(LdapUser user)
    {
        var details = $"CN={user.CN},OU={user.OU},DC={user.DC}\n";
        if (!string.IsNullOrEmpty(user.Email)) details += $"  - Email: {user.Email}\n";
        if (!string.IsNullOrEmpty(user.Phone)) details += $"  - Phone: {user.Phone}\n";
        if (!string.IsNullOrEmpty(user.Groups)) details += $"  - Groups: {user.Groups}\n";
        if (!string.IsNullOrEmpty(user.Description)) details += $"  - Description: {user.Description}\n";
        if (!string.IsNullOrEmpty(user.Department)) details += $"  - Department: {user.Department}\n";
        if (!string.IsNullOrEmpty(user.SSN)) details += $"  - SSN: {user.SSN}\n";
        if (!string.IsNullOrEmpty(user.Salary)) details += $"  - Salary: {user.Salary}\n";
        if (!string.IsNullOrEmpty(user.Title)) details += $"  - Title: {user.Title}\n";
        if (!string.IsNullOrEmpty(user.Password)) details += $"  - Password: {user.Password} (cleartext in description)\n";
        if (!string.IsNullOrEmpty(user.Permissions)) details += $"  - Permissions: {user.Permissions}\n";
        return details;
    }

    private class LdapUser
    {
        public string CN { get; set; } = "";
        public string OU { get; set; } = "";
        public string DC { get; set; } = "";
        public string Email { get; set; } = "";
        public string Phone { get; set; } = "";
        public string Groups { get; set; } = "";
        public string Description { get; set; } = "";
        public string Department { get; set; } = "";
        public string SSN { get; set; } = "";
        public string Salary { get; set; } = "";
        public string Title { get; set; } = "";
        public string Password { get; set; } = "";
        public string Permissions { get; set; } = "";
    }
}

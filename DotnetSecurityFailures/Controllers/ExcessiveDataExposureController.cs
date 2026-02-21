using Microsoft.AspNetCore.Mvc;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating Excessive Data Exposure vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how APIs can expose more data than necessary.
/// 
/// Used by: /vulnerabilities/excessive-data-exposure
/// </summary>
[ApiController]
[Route("api/vulnerabilities/excessive-data-exposure")]
public class ExcessiveDataExposureController : VulnerabilityDemoControllerBase
{
    public ExcessiveDataExposureController(ILogger<ExcessiveDataExposureController> logger)
        : base(logger, "excessive-data-exposure")
    {
    }

    // VULNERABLE: Returns entire user object including sensitive fields
    [HttpGet("users")]
    public IActionResult GetUsers()
    {
        LogDemoActivity("GetUsers", "Returning full user objects with sensitive data");
        
        var users = new[]
        {
            new
            {
                id = 1,
                username = "admin",
                email = "admin@company.com",
                password = "hashed_admin_pass_123",
                passwordSalt = "random_salt_abc",
                apiKey = "sk_live_admin_key_xyz",
                ssn = "123-45-6789",
                creditCard = "4532-1234-5678-9999",
                salary = 150000,
                role = "Administrator",
                isActive = true,
                lastLoginIp = "192.168.1.100",
                securityQuestions = new[]
                {
                    new { question = "Mother's maiden name?", answer = "Smith" },
                    new { question = "First pet?", answer = "Fluffy" }
                }
            },
            new
            {
                id = 2,
                username = "john_doe",
                email = "john@company.com",
                password = "hashed_user_pass_456",
                passwordSalt = "random_salt_def",
                apiKey = "sk_live_user_key_abc",
                ssn = "987-65-4321",
                creditCard = "5555-4444-3333-2222",
                salary = 75000,
                role = "User",
                isActive = true,
                lastLoginIp = "192.168.1.101",
                securityQuestions = new[]
                {
                    new { question = "Mother's maiden name?", answer = "Johnson" },
                    new { question = "First pet?", answer = "Rex" }
                }
            }
        };

        return Ok(users);
    }

    [HttpGet("user/{id}")]
    public IActionResult GetUser(int id)
    {
        LogDemoActivity("GetUser", $"Returning full user object for ID: {id}");
        
        // VULNERABLE: Exposes all user data
        var user = new
        {
            id = id,
            username = "john_doe",
            email = "john@company.com",
            password = "hashed_password_123",
            passwordSalt = "salt_xyz",
            apiKey = "sk_live_abc123",
            ssn = "123-45-6789",
            creditCard = "4532-****-****-1234",
            salary = 75000,
            role = "User",
            internalNotes = "Performance review pending",
            lastLoginIp = "192.168.1.50"
        };

        return Ok(user);
    }
}

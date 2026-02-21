using Microsoft.AspNetCore.Mvc;
using DotnetSecurityFailures.Models;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating Missing Authorization Check vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how API endpoints can be accessed without proper authorization checks.
/// 
/// Used by: /vulnerabilities/missing-authorization
/// </summary>
[ApiController]
[Route("api/vulnerabilities/missing-authorization")]
public class MissingAuthorizationController : VulnerabilityDemoControllerBase
{
    public MissingAuthorizationController(ILogger<MissingAuthorizationController> logger)
        : base(logger, "missing-authorization")
    {
    }

    // VULNERABLE: No authorization check!
    [HttpGet("users")]
    public IActionResult GetAllUsers()
    {
        LogDemoActivity("GetAllUsers", "Accessed without authorization check");
        
        var users = new List<User>
        {
            new() { Id = 1, Email = "admin@company.com", Password = "hashed123", Role = "Admin" },
            new() { Id = 2, Email = "user@company.com", Password = "hashed456", Role = "User" },
            new() { Id = 3, Email = "john@company.com", Password = "hashed789", Role = "User" }
        };
        
        return Ok(users);
    }
    
    // VULNERABLE: No authorization check on dangerous operation!
    [HttpDelete("delete-user")]
    public IActionResult DeleteUser([FromQuery] int id)
    {
        LogDemoActivity("DeleteUser", $"Deleting user {id} without authorization");
        
        return Ok(new { message = $"User ID {id} deleted successfully" });
    }
}

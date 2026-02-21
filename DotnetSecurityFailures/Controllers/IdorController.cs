using Microsoft.AspNetCore.Mvc;
using DotnetSecurityFailures.Models;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating IDOR (Insecure Direct Object Reference) vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how IDOR allows access to other users' data by modifying ID parameters.
/// 
/// Used by: /vulnerabilities/idor
/// </summary>
[ApiController]
[Route("api/vulnerabilities/idor")]
public class IdorController : VulnerabilityDemoControllerBase
{
    public IdorController(ILogger<IdorController> logger)
        : base(logger, "idor")
    {
    }

    // VULNERABLE: No authorization check - anyone can access any profile!
    [HttpGet("profile")]
    public IActionResult GetProfile([FromQuery] int? id)
    {
        LogDemoActivity("GetProfile", $"Accessing profile ID: {id}");
        
        var user = new User
        {
            Id = id ?? 1,
            Email = "victim@company.com",
            Name = "Current User",
            SSN = "123-45-6789",
            CreditCard = "4111-1111-1111-1111",
            Role = "User"
        };
        
        return Ok(user);
    }

    // VULNERABLE: Accepts role from user input during registration!
    [HttpPost("register")]
    public IActionResult Register([FromBody] RegistrationRequest request)
    {
        LogDemoActivity("Register", $"Registering user: {request.Username} with role: {request.Role}");
        
        if (string.IsNullOrWhiteSpace(request.Username) || 
            string.IsNullOrWhiteSpace(request.Email) || 
            string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new { success = false, message = "All fields are required" });
        }

        // VULNERABILITY: Directly using user-provided role without validation
        var user = new User
        {
            Id = new Random().Next(1000, 9999),
            Name = request.Username,
            Email = request.Email,
            Password = $"hashed_{request.Password}",
            Role = request.Role ?? "User" // User can control this!
        };

        return Ok(new 
        { 
            success = true,
            message = $"User registered successfully with role: {user.Role}",
            userId = user.Id,
            username = user.Name,
            email = user.Email,
            role = user.Role,
            isPrivileged = user.Role == "Admin" || user.Role == "SuperAdmin"
        });
    }

    public class RegistrationRequest
    {
        public string Username { get; set; } = "";
        public string Email { get; set; } = "";
        public string Password { get; set; } = "";
        public string? Role { get; set; } // VULNERABLE: Should not be accepted from client!
    }
}

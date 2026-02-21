using Microsoft.AspNetCore.Mvc;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating Mass Assignment vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how mass assignment can allow attackers to modify unintended properties.
/// 
/// Used by: /vulnerabilities/mass-assignment
/// </summary>
[ApiController]
[Route("api/vulnerabilities/mass-assignment")]
public class MassAssignmentController : VulnerabilityDemoControllerBase
{
    private static UserProfile currentUser = new()
    {
        Id = 1,
        Name = "John Doe",
        Email = "john@example.com",
        Balance = 100.00m,
        PasswordHash = "hashed_password_123"
    };

    public MassAssignmentController(ILogger<MassAssignmentController> logger)
        : base(logger, "mass-assignment")
    {
    }

    [HttpGet("profile")]
    public IActionResult GetProfile()
    {
        LogDemoActivity("GetProfile", "Retrieving current profile");
        
        return Ok(new
        {
            id = currentUser.Id,
            name = currentUser.Name,
            email = currentUser.Email,
            balance = currentUser.Balance
        });
    }

    // VULNERABLE - accepts all properties from request
    [HttpPost("update")]
    public IActionResult UpdateProfile([FromBody] UserProfile model)
    {
        model.Id = currentUser.Id;
        currentUser = model;

        return Ok(new
        {
            success = true,
            message = "Profile updated",
            user = model
        });
    }

    [HttpPost("reset")]
    public IActionResult ResetProfile()
    {
        LogDemoActivity("ResetProfile", "Resetting profile to defaults");
        
        currentUser = new()
        {
            Id = 1,
            Name = "John Doe",
            Email = "john@example.com",
            Balance = 100.00m,
            PasswordHash = "hashed_password_123"
        };
        
        return Ok(new { success = true, message = "Profile reset" });
    }

    public class UserProfile
    {
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string Email { get; set; } = "";
        public decimal Balance { get; set; }
        public string PasswordHash { get; set; } = "";
    }
}

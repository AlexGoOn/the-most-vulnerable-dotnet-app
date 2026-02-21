using Microsoft.AspNetCore.Mvc;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating Privilege Escalation vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how accepting sensitive parameters (like role) from user input leads
/// to privilege escalation attacks.
/// 
/// Used by: /vulnerabilities/privilege-escalation
/// </summary>
[ApiController]
[Route("api/user")]
public class PrivilegeEscalationController : VulnerabilityDemoControllerBase
{
    private static int _nextUserId = 1;
    private static readonly List<RegisteredUser> _registeredUsers = new();

    public PrivilegeEscalationController(ILogger<PrivilegeEscalationController> logger)
        : base(logger, "privilege-escalation")
    {
    }

    // VULNERABLE: Accepts role from user input without validation
    [HttpPost("register")]
    public IActionResult Register([FromBody] RegistrationRequest request)
    {
        LogDemoActivity("Register", $"Registration attempt - Username: {request.Username}, Email: {request.Email}, Role: {request.Role ?? "User"}");
        
        if (string.IsNullOrWhiteSpace(request.Username) || 
            string.IsNullOrWhiteSpace(request.Email) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            return BadRequest(new { success = false, message = "Username, email, and password are required" });
        }

        // VULNERABILITY: Accepting role directly from user input!
        // This is the critical flaw - users can elevate their own privileges
        var role = request.Role ?? "User"; // Default to "User" if not provided
        
        var user = new RegisteredUser
        {
            UserId = _nextUserId++,
            Username = request.Username,
            Email = request.Email,
            Role = role, // DANGEROUS: User-controlled value!
            CreatedAt = DateTime.UtcNow,
            IsPrivileged = role.Equals("Admin", StringComparison.OrdinalIgnoreCase) || 
                          role.Equals("SuperAdmin", StringComparison.OrdinalIgnoreCase)
        };

        _registeredUsers.Add(user);

        LogDemoActivity("RegisterSuccess", 
            $"User registered - ID: {user.UserId}, Username: {user.Username}, Role: {user.Role}, Privileged: {user.IsPrivileged}");

        return Ok(new
        {
            success = true,
            message = "User registered successfully",
            userId = user.UserId,
            username = user.Username,
            email = user.Email,
            role = user.Role,
            isPrivileged = user.IsPrivileged
        });
    }

    [HttpGet("list")]
    public IActionResult ListUsers()
    {
        return Ok(new
        {
            success = true,
            users = _registeredUsers.Select(u => new
            {
                u.UserId,
                u.Username,
                u.Email,
                u.Role,
                u.IsPrivileged,
                u.CreatedAt
            })
        });
    }

    [HttpPost("reset")]
    public IActionResult ResetUsers()
    {
        _registeredUsers.Clear();
        _nextUserId = 1;
        LogDemoActivity("Reset", "All users cleared");
        
        return Ok(new { success = true, message = "All users cleared" });
    }

    // VULNERABLE: Request model that accepts role from user
    public class RegistrationRequest
    {
        public string Username { get; set; } = "";
        public string Email { get; set; } = "";
        public string Password { get; set; } = "";
        
        // VULNERABILITY: This should NOT be in the request model!
        // Role should be assigned server-side only
        public string? Role { get; set; }
    }

    private class RegisteredUser
    {
        public int UserId { get; set; }
        public string Username { get; set; } = "";
        public string Email { get; set; } = "";
        public string Role { get; set; } = "User";
        public bool IsPrivileged { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}

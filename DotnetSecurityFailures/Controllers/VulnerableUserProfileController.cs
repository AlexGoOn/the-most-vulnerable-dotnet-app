using Microsoft.AspNetCore.Mvc;

namespace DotnetSecurityFailures.Controllers;

[ApiController]
[Route("api/user")]
public class VulnerableUserProfileController : ControllerBase
{
    private static readonly Dictionary<int, UserProfile> Users = new()
    {
        {
            1, new UserProfile
            {
                Id = 1,
                Name = "Admin User",
                Email = "admin@company.com",
                Role = "Administrator",
                Ssn = "123-45-6789",
                Salary = 150000
            }
        },
        {
            2, new UserProfile
            {
                Id = 2,
                Name = "Alice Smith",
                Email = "alice@company.com",
                CreditCard = "4111-1111-1111-1111",
                Address = "123 Main St"
            }
        },
        {
            3, new UserProfile
            {
                Id = 3,
                Name = "Bob Johnson",
                Email = "bob@company.com",
                Ssn = "987-65-4321",
                MedicalRecords = "Confidential"
            }
        },
        {
            4, new UserProfile
            {
                Id = 4,
                Name = "Carol White",
                Email = "carol@company.com",
                BankAccount = "123456789",
                Balance = 50000
            }
        },
        {
            5, new UserProfile
            {
                Id = 5,
                Name = "John Doe",
                Email = "john.doe@company.com",
                Phone = "+1-555-0105"
            }
        }
    };

    // VULNERABLE: No authorization check
    [HttpGet("profile/{id}")]
    public IActionResult GetProfile(int id)
    {
        // Simulated current user (should come from authentication)
        const int currentUserId = 5;

        if (!Users.TryGetValue(id, out var user))
        {
            return NotFound(new { success = false, message = "User not found" });
        }

        // VULNERABILITY: No ownership verification!
        // The application returns any user's data without checking
        // if the current user (ID 5) has permission to access it
        return Ok(new
        {
            success = true,
            authorized = id == currentUserId,
            data = user
        });
    }

    public class UserProfile
    {
        public int Id { get; set; }
        public string Name { get; set; } = "";
        public string Email { get; set; } = "";
        public string? Phone { get; set; }
        public string? Role { get; set; }
        public string? Ssn { get; set; }
        public int? Salary { get; set; }
        public string? CreditCard { get; set; }
        public string? Address { get; set; }
        public string? MedicalRecords { get; set; }
        public string? BankAccount { get; set; }
        public int? Balance { get; set; }
    }
}

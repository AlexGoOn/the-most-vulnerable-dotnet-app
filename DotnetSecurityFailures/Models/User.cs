namespace DotnetSecurityFailures.Models;

public class User
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? SSN { get; set; }
    public string? CreditCard { get; set; }
    public string Role { get; set; } = "User";
}

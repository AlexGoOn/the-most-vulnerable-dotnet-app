using Microsoft.AspNetCore.Mvc;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating Data in URLs vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how sensitive data exposed in URLs can be logged and intercepted.
/// 
/// Used by: /vulnerabilities/data-in-urls
/// </summary>
[ApiController]
[Route("api/password-reset")]
public class DataInUrlsController : VulnerabilityDemoControllerBase
{
    public DataInUrlsController(ILogger<DataInUrlsController> logger)
        : base(logger, "data-in-urls")
    {
    }

    /// <summary>
    /// VULNERABLE: Generates a password reset link with sensitive data exposed in the URL
    /// This demonstrates how passwords and tokens should NEVER be in URLs
    /// </summary>
    [HttpPost("generate-link")]
    [IgnoreAntiforgeryToken] // Allow the demo to work without CSRF protection
    public IActionResult GenerateResetLink([FromBody] ResetLinkRequest request)
    {
        LogDemoActivity("GenerateResetLink", $"Generating reset link for: {request.Email}");

        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return BadRequest(new
            {
                success = false,
                message = "Email and password are required"
            });
        }

        // Generate a token (simulated)
        var token = Guid.NewGuid().ToString("N").Substring(0, 16);

        // VULNERABLE: Building URL with sensitive data
        var baseUrl = $"{Request.Scheme}://{Request.Host}";
        var resetLink = $"{baseUrl}/api/password-reset/reset?email={Uri.EscapeDataString(request.Email)}&token={token}&newPassword={Uri.EscapeDataString(request.NewPassword)}";

        LogDemoActivity("VulnerableLink", $"EXPOSED IN URL: {resetLink}");

        var exposures = new[]
        {
            "Browser History - Password permanently stored",
            "Server Access Logs - Full URL logged",
            "Proxy Logs - Corporate proxies see everything",
            "Referer Header - Leaked to external sites if user clicks links",
            "Shared Links - User might accidentally share this URL"
        };

        return Ok(new
        {
            success = true,
            resetLink = resetLink,
            exposures = exposures,
            warning = "CRITICAL: Password exposed in URL! This will be logged everywhere!"
        });
    }

    /// <summary>
    /// VULNERABLE: Accepts password reset via GET with all data in URL
    /// This should NEVER be done - passwords should be in POST body
    /// </summary>
    [HttpGet("reset")]
    public IActionResult ResetPasswordVulnerable(
        [FromQuery] string email,
        [FromQuery] string token,
        [FromQuery] string newPassword)
    {
        LogDemoActivity("ResetPassword", $"VULNERABILITY: Password in URL for {email}");

        if (string.IsNullOrWhiteSpace(email) || 
            string.IsNullOrWhiteSpace(token) || 
            string.IsNullOrWhiteSpace(newPassword))
        {
            return BadRequest(new
            {
                success = false,
                message = "All parameters are required"
            });
        }

        // Simulate password reset
        return Ok(new
        {
            success = true,
            message = "Password reset successful (demonstration only)",
            warning = "This password was visible in the URL and has been logged!"
        });
    }

    public class ResetLinkRequest
    {
        public string Email { get; set; } = "";
        public string NewPassword { get; set; } = "";
    }
}

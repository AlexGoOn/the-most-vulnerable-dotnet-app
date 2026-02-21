using Microsoft.AspNetCore.Mvc;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating Password Reset Poisoning vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how password reset functionality can be exploited through Host header injection.
/// 
/// Used by: /vulnerabilities/password-reset-poisoning
/// </summary>
[ApiController]
[Route("api/vulnerabilities/password-reset-poisoning")]
public class PasswordResetPoisoningController : VulnerabilityDemoControllerBase
{
    public PasswordResetPoisoningController(ILogger<PasswordResetPoisoningController> logger)
        : base(logger, "password-reset-poisoning")
    {
    }

    // VULNERABLE: Uses Host header to build reset link
    [HttpPost("request-reset")]
    public IActionResult RequestPasswordReset([FromBody] ResetRequest request)
    {
        LogDemoActivity("RequestPasswordReset", $"Reset requested for: {request.Email}");
        
        if (string.IsNullOrWhiteSpace(request.Email))
        {
            return BadRequest(new { success = false, message = "Email is required" });
        }

        // Generate reset token
        var resetToken = Guid.NewGuid().ToString("N");

        // VULNERABLE: Using Host header from request
        var host = HttpContext.Request.Headers["Host"].ToString();
        var scheme = HttpContext.Request.Scheme;
        
        // DANGEROUS: Attacker can control this URL via Host header
        var resetLink = $"{scheme}://{host}/reset-password?token={resetToken}";

        LogDemoActivity("ResetLinkGenerated", $"Reset link: {resetLink}");

        return Ok(new
        {
            success = true,
            message = "Password reset email sent",
            resetLink = resetLink, // Exposed for demo purposes
            resetToken = resetToken,
            warning = host.Contains("evil") || host.Contains("attacker") 
                ? "HOST HEADER INJECTION DETECTED! Link points to attacker domain!" 
                : "Reset link generated"
        });
    }

    [HttpPost("reset-password")]
    public IActionResult ResetPassword([FromBody] ResetPasswordRequest request)
    {
        LogDemoActivity("ResetPassword", $"Password reset with token: {request.Token}");
        
        if (string.IsNullOrWhiteSpace(request.Token) || string.IsNullOrWhiteSpace(request.NewPassword))
        {
            return BadRequest(new { success = false, message = "Token and new password are required" });
        }

        return Ok(new
        {
            success = true,
            message = "Password successfully reset"
        });
    }

    public class ResetRequest
    {
        public string Email { get; set; } = "";
    }

    public class ResetPasswordRequest
    {
        public string Token { get; set; } = "";
        public string NewPassword { get; set; } = "";
    }
}

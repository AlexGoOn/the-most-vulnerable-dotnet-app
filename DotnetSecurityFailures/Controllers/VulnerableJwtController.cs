using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Text.Json;

namespace DotnetSecurityFailures.Controllers;

[ApiController]
[Route("api/jwt")]
[IgnoreAntiforgeryToken] // INTENTIONALLY VULNERABLE: Demo controller bypasses CSRF protection
public class VulnerableJwtController : ControllerBase
{
    [HttpPost("validate")]
    public IActionResult ValidateToken([FromBody] JwtValidationRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Token))
        {
            return BadRequest(new { error = "Token is required" });
        }

        try
        {
            // VULNERABLE: Developer decided to parse JWT manually instead of using AddJwtBearer
            // "It's just JSON with Base64 - I can validate it myself!"
            var parts = request.Token.Split('.');

            if (parts.Length < 2)
            {
                return BadRequest(new { error = "Invalid JWT format" });
            }

            // Decode header
            var headerJson = Encoding.UTF8.GetString(Convert.FromBase64String(AddPadding(parts[0])));
            var header = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(headerJson);

            // Decode payload (NO SIGNATURE VALIDATION!)
            var payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(AddPadding(parts[1])));
            var payload = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(payloadJson);

            // Check for vulnerabilities
            if (header != null && header.ContainsKey("alg"))
            {
                var alg = header["alg"].GetString();

                if (alg?.ToLower() == "none")
                {
                    return Ok(new
                    {
                        valid = true,
                        exploited = true,
                        vulnerability = "ALGORITHM_NONE",
                        attackType = "Algorithm Confusion",
                        message = "JWT ALGORITHM NONE ATTACK! Bypasses signature verification!",
                        payload = payloadJson
                    });
                }
            }

            if (parts.Length == 2)
            {
                return Ok(new
                {
                    valid = true,
                    exploited = true,
                    vulnerability = "MISSING_SIGNATURE",
                    attackType = "Signature Removal",
                    message = "JWT SIGNATURE REMOVAL! Token without signature section!",
                    payload = payloadJson
                });
            }

            // Check if payload was modified
            if (payload != null && payload.ContainsKey("role"))
            {
                var role = payload["role"].GetString();
                if (role == "admin" || role == "administrator")
                {
                    return Ok(new
                    {
                        valid = true,
                        exploited = true,
                        vulnerability = "PRIVILEGE_ESCALATION",
                        attackType = "Privilege Escalation",
                        message = "JWT TAMPERING! Modified payload without valid signature!",
                        payload = payloadJson
                    });
                }
            }

            return Ok(new
            {
                valid = true,
                exploited = false,
                message = "Token decoded successfully!\n\n" +
                         "WARNING: No signature validation performed!\n" +
                         "This token was accepted without verification.",
                payload = payloadJson
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }

    private static string AddPadding(string base64)
    {
        switch (base64.Length % 4)
        {
            case 2: return base64 + "==";
            case 3: return base64 + "=";
            default: return base64;
        }
    }
}

public class JwtValidationRequest
{
    public string Token { get; set; } = "";
}

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Cors;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating CORS Misconfiguration vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how overly permissive CORS policies can be exploited.
/// 
/// Used by: /vulnerabilities/cors-misconfiguration
/// </summary>
[ApiController]
[Route("api")]
[EnableCors("VulnerablePolicy")] // VULNERABLE: Applies permissive CORS policy
public class CorsMisconfigurationController : VulnerabilityDemoControllerBase
{
    public CorsMisconfigurationController(ILogger<CorsMisconfigurationController> logger)
        : base(logger, "cors-misconfiguration")
    {
    }

    // Endpoint that attacker.html targets
    [HttpGet("user/balance")]
    public IActionResult GetUserBalance()
    {
        LogDemoActivity("GetUserBalance", "Retrieving user balance with permissive CORS");
        
        // VULNERABLE: This endpoint allows cross-origin requests from ANY origin with credentials
        // An attacker can call this from their malicious site and steal the data
        return Ok(new
        {
            username = "john.doe@example.com",
            accountBalance = 15420.50m,
            accountNumber = "****7890",
            apiKey = "sk_live_51H7xYz2KePxqVz3M9nHt8FjK2s4Q1vLm9X"
        });
    }

    [HttpGet("vulnerabilities/cors-misconfiguration/sensitive-data")]
    public IActionResult GetSensitiveData()
    {
        LogDemoActivity("GetSensitiveData", "Retrieving sensitive data with permissive CORS");
        
        // This endpoint has overly permissive CORS (configured in Program.cs)
        return Ok(new
        {
            userEmail = "admin@company.com",
            apiKey = "sk_live_abc123xyz789",
            balance = 5000.00m,
            creditCard = "4532-****-****-1234",
            ssn = "123-45-6789"
        });
    }

    [HttpPost("vulnerabilities/cors-misconfiguration/transfer")]
    public IActionResult TransferFunds([FromBody] TransferRequest request)
    {
        LogDemoActivity("TransferFunds", $"Transfer to {request.ToAccount}: ${request.Amount}");
        
        return Ok(new
        {
            success = true,
            message = $"Transferred ${request.Amount} to {request.ToAccount}",
            transactionId = Guid.NewGuid().ToString()
        });
    }

    public class TransferRequest
    {
        public string ToAccount { get; set; } = "";
        public decimal Amount { get; set; }
    }
}

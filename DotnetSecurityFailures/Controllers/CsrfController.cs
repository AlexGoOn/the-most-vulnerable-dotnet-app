using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Cors;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating CSRF (Cross-Site Request Forgery) vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how CSRF attacks can perform unauthorized actions on behalf of authenticated users.
/// 
/// Used by: /vulnerabilities/csrf
/// </summary>
[ApiController]
[Route("api/vulnerabilities/csrf")]
[EnableCors("VulnerablePolicy")] // VULNERABLE: Allows cross-origin requests from any origin
public class CsrfController : VulnerabilityDemoControllerBase
{
    private static decimal userBalance = 1000.00m;
    private static string userEmail = "user@example.com";

    public CsrfController(ILogger<CsrfController> logger)
        : base(logger, "csrf")
    {
    }

    [HttpGet("balance")]
    public IActionResult GetBalance()
    {
        LogDemoActivity("GetBalance", $"Current balance: ${userBalance}");
        
        return Ok(new
        {
            balance = userBalance,
            currency = "USD",
            userEmail = userEmail
        });
    }

    // VULNERABLE: No CSRF protection + permissive CORS
    // This allows cross-origin requests from malicious sites
    [HttpPost("purchase")]
    [IgnoreAntiforgeryToken]
    public IActionResult MakePurchase([FromBody] PurchaseRequest request)
    {
        LogDemoActivity("MakePurchase", $"Purchasing {request.ProductName} for ${request.Amount}");
        
        if (userBalance >= request.Amount)
        {
            userBalance -= request.Amount;
            
            return Ok(new
            {
                success = true,
                message = $"Purchased {request.ProductName}",
                amount = request.Amount,
                newBalance = userBalance,
                userEmail = userEmail
            });
        }

        return BadRequest(new
        {
            success = false,
            error = "Insufficient funds",
            balance = userBalance
        });
    }

    [HttpPost("reset")]
    [IgnoreAntiforgeryToken]
    public IActionResult ResetBalance()
    {
        LogDemoActivity("ResetBalance", "Resetting balance to $1000");
        
        userBalance = 1000.00m;
        return Ok(new { success = true, balance = userBalance });
    }

    public class PurchaseRequest
    {
        public string ProductName { get; set; } = "";
        public decimal Amount { get; set; }
    }
}

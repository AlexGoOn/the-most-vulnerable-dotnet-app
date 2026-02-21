using Microsoft.AspNetCore.Mvc;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating API Keys Exposure vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how API keys can be exposed in client-side code and responses.
/// 
/// Used by: /vulnerabilities/api-keys-exposure
/// </summary>
[ApiController]
[Route("api/vulnerabilities/api-keys-exposure")]
[IgnoreAntiforgeryToken] // For demo purposes - this is also a vulnerability!
public class ApiKeysExposureController : VulnerabilityDemoControllerBase
{
    public ApiKeysExposureController(ILogger<ApiKeysExposureController> logger)
        : base(logger, "api-keys-exposure")
    {
    }

    // VULNERABLE: Exposes API keys in response
    [HttpGet("config")]
    public IActionResult GetConfig()
    {
        LogDemoActivity("GetConfig", "Exposing API keys in configuration");
        
        // DANGEROUS: Sending API keys to client
        return Ok(new
        {
            stripeApiKey = "sk_live_51HyTnKLJr8xYz9ABC123XYZ789",
            stripePublishableKey = "pk_live_51HyTnKLJr8xYz9XYZ123ABC789",
            awsAccessKey = "AKIAIOSFODNN7EXAMPLE",
            awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            googleMapsApiKey = "AIzaSyBxyz123ABC789_ExampleKey",
            sendGridApiKey = "SG.abc123xyz789.ExampleSendGridKey",
            twilioAccountSid = "ACabc123xyz789exampleSid",
            twilioAuthToken = "abc123xyz789exampleToken",
            databaseConnectionString = "Server=prod-db.company.com;Database=Production;User=sa;Password=SuperSecret123!"
        });
    }

    [HttpGet("keys")]
    public IActionResult GetApiKeys()
    {
        LogDemoActivity("GetApiKeys", "Exposing various API keys");
        
        return Ok(new
        {
            services = new object[]
            {
                new { name = "Stripe", key = "sk_live_51HyTnKLJr8xYz9ABC123" },
                new { name = "AWS", accessKey = "AKIAIOSFODNN7EXAMPLE", secretKey = "wJalrXUtnFEMI/K7MDENG" },
                new { name = "Google Maps", key = "AIzaSyBxyz123ABC789" },
                new { name = "SendGrid", key = "SG.abc123xyz789" }
            }
        });
    }

    [HttpPost("initialize")]
    public IActionResult Initialize([FromBody] InitRequest request)
    {
        LogDemoActivity("Initialize", $"Initializing service: {request.Service}");
        
        // DANGEROUS: Including API keys in response based on service type
        var apiKey = request.Service?.ToLower() switch
        {
            "stripe" => "sk_live_51HyTnKLJr8xYz9ABC123XYZ789",
            "aws" => "AKIAIOSFODNN7EXAMPLE",
            "sendgrid" => "SG.abc123xyz789.ExampleSendGridKey",
            _ => "unknown_service_key"
        };

        return Ok(new
        {
            success = true,
            service = request.Service,
            apiKey = apiKey,
            message = "Service initialized with API key"
        });
    }

    public class InitRequest
    {
        public string Service { get; set; } = "";
    }
}

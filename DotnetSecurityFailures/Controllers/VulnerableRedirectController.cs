using Microsoft.AspNetCore.Mvc;

namespace DotnetSecurityFailures.Controllers;

[ApiController]
[Route("api/redirect")]
public class VulnerableRedirectController : ControllerBase
{
    // VULNERABLE: Raw HTTP response construction with user input
    [HttpGet("vulnerable")]
    public async Task VulnerableRedirect([FromQuery] string url)
    {
        if (string.IsNullOrWhiteSpace(url))
        {
            Response.StatusCode = 400;
            await Response.WriteAsync("URL parameter is required");
            return;
        }

        // DANGER: URL decode to convert %0d%0a to actual CRLF characters
        // This is where the vulnerability actually happens
        var decodedUrl = System.Web.HttpUtility.UrlDecode(url);

        // DANGER: Building raw HTTP response with user input
        // This demonstrates how CRLF injection works
        var rawResponse = "HTTP/1.1 302 Found\r\n" +
                      $"Location: {decodedUrl}\r\n" +
                      "X-Powered-By: VulnerableApp\r\n" +
                      "Content-Type: text/html; charset=utf-8\r\n" +
                      "Server: Kestrel\r\n" +
                      "\r\n" +
                      "<html><body>Redirecting...</body></html>";

        // Return as plain text to show the vulnerability
        Response.ContentType = "text/plain";
        await Response.WriteAsync("=== RAW HTTP RESPONSE (Vulnerable) ===\n\n");
        await Response.WriteAsync(rawResponse);
        await Response.WriteAsync("\n\n=== END OF RESPONSE ===");
    }
}

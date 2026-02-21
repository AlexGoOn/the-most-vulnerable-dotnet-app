using Microsoft.AspNetCore.Mvc;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating SSRF (Server-Side Request Forgery) vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how SSRF allows attackers to make requests to internal resources.
/// 
/// Used by: /vulnerabilities/ssrf
/// </summary>
[ApiController]
[Route("api/vulnerabilities/ssrf")]
public class SsrfController : VulnerabilityDemoControllerBase
{
    private readonly HttpClient _httpClient;

    public SsrfController(
        ILogger<SsrfController> logger,
        IHttpClientFactory httpClientFactory)
        : base(logger, "ssrf")
    {
        _httpClient = httpClientFactory.CreateClient();
        _httpClient.Timeout = TimeSpan.FromSeconds(5);
    }

    // VULNERABLE: No URL validation - allows SSRF attacks
    [HttpGet("fetch")]
    public async Task<IActionResult> FetchUrl([FromQuery] string url)
    {
        LogDemoActivity("FetchUrl", $"Fetching URL: {url}");
        
        if (string.IsNullOrWhiteSpace(url))
        {
            return BadRequest(new { success = false, message = "URL is required" });
        }

        try
        {
            // VULNERABLE: Fetches ANY URL without validation
            var response = await _httpClient.GetAsync(url);
            var content = await response.Content.ReadAsStringAsync();

            return Ok(new
            {
                success = true,
                url = url,
                statusCode = (int)response.StatusCode,
                contentType = response.Content.Headers.ContentType?.ToString(),
                content = content.Length > 1000 ? content.Substring(0, 1000) + "..." : content,
                isVulnerable = IsInternalUrl(url)
            });
        }
        catch (HttpRequestException ex)
        {
            return Ok(new
            {
                success = true,
                url = url,
                error = ex.Message,
                isVulnerable = IsInternalUrl(url)
            });
        }
        catch (TaskCanceledException)
        {
            return Ok(new
            {
                success = true,
                url = url,
                error = "Request timeout",
                isVulnerable = IsInternalUrl(url)
            });
        }
    }

    private bool IsInternalUrl(string url)
    {
        var urlLower = url.ToLower();
        return urlLower.Contains("localhost") ||
               urlLower.Contains("127.0.0.1") ||
               urlLower.Contains("169.254.169.254") ||
               urlLower.Contains("192.168") ||
               urlLower.Contains("10.") ||
               urlLower.Contains("172.16") ||
               urlLower.StartsWith("file://");
    }
}

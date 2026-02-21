using Microsoft.AspNetCore.Mvc;
using System.Xml.Linq;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating SSRF via SVG File Upload vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how SVG processing with external resource embedding can lead to SSRF attacks.
/// 
/// Real-world scenario: SVG Image Embedder service that converts external image 
/// references into embedded data URIs to create standalone SVG files.
/// Common use cases: logo optimization, avatar processing, PDF generation
/// 
/// Used by: /vulnerabilities/ssrf-file-upload
/// </summary>
[ApiController]
[Route("api/vulnerabilities/xss-svg")]
public class XssSvgController : VulnerabilityDemoControllerBase
{
    private readonly HttpClient _httpClient;

    public XssSvgController(
        ILogger<XssSvgController> logger,
        IHttpClientFactory httpClientFactory)
        : base(logger, "ssrf-file-upload")
    {
        _httpClient = httpClientFactory.CreateClient();
        _httpClient.Timeout = TimeSpan.FromSeconds(5);
    }

    // VULNERABLE - Embeds external images by fetching them server-side
    // Real scenario: Creating standalone SVG files by embedding external resources
    [HttpPost("process")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> ProcessSvg([FromBody] SvgUploadRequest request)
    {
        LogDemoActivity("EmbedExternalImages", "Embedding external images into SVG (SSRF risk)");
        
        if (string.IsNullOrWhiteSpace(request.SvgContent))
        {
            return BadRequest(new { success = false, message = "SVG content is required" });
        }

        var externalRequests = new List<ExternalRequestInfo>();

        try
        {
            var doc = XDocument.Parse(request.SvgContent);
            var ns = XNamespace.Get("http://www.w3.org/2000/svg");

            var images = doc.Descendants(ns + "image")
                .Select(e => e.Attribute("href")?.Value ?? e.Attribute(XNamespace.Get("http://www.w3.org/1999/xlink") + "href")?.Value)
                .Where(href => !string.IsNullOrEmpty(href) && !href.StartsWith("data:"))
                .ToList();

            // DANGEROUS: Fetch each external URL (SSRF risk)
            foreach (var href in images)
            {
                var requestInfo = new ExternalRequestInfo
                {
                    Url = href,
                    IsInternal = IsInternalUrl(href)
                };

                try
                {
                    var response = await _httpClient.GetAsync(href);
                    requestInfo.StatusCode = (int)response.StatusCode;
                    requestInfo.Success = response.IsSuccessStatusCode;

                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        requestInfo.ContentPreview = content.Length > 200 
                            ? content.Substring(0, 200) + "..." 
                            : content;
                        requestInfo.ContentLength = content.Length;
                    }
                    else
                    {
                        requestInfo.Error = $"HTTP {response.StatusCode}";
                    }
                }
                catch (HttpRequestException ex)
                {
                    requestInfo.Success = false;
                    requestInfo.Error = ex.Message;
                }
                catch (TaskCanceledException)
                {
                    requestInfo.Success = false;
                    requestInfo.Error = "Request timeout";
                }

                externalRequests.Add(requestInfo);
            }

            return Ok(new
            {
                success = true,
                svgContent = request.SvgContent,
                externalRequests = externalRequests,
                isVulnerable = externalRequests.Any(r => r.IsInternal)
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new
            {
                success = false,
                message = $"Failed to parse SVG: {ex.Message}"
            });
        }
    }

    private bool IsInternalUrl(string url)
    {
        try
        {
            var uri = new Uri(url);
            var host = uri.Host.ToLower();

            return host == "localhost" ||
                   host == "127.0.0.1" ||
                   host == "169.254.169.254" ||
                   host.StartsWith("192.168.") ||
                   host.StartsWith("10.") ||
                   host.StartsWith("172.16.") ||
                   host.EndsWith(".local") ||
                   host.EndsWith(".internal");
        }
        catch
        {
            return false;
        }
    }

    public class SvgUploadRequest
    {
        public string SvgContent { get; set; } = "";
    }

    public class ExternalRequestInfo
    {
        public string Url { get; set; } = "";
        public bool Success { get; set; }
        public int StatusCode { get; set; }
        public string Error { get; set; } = "";
        public string ContentPreview { get; set; } = "";
        public int ContentLength { get; set; }
        public bool IsInternal { get; set; }
    }
}

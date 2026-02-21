using Microsoft.AspNetCore.Mvc;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating Path Traversal vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how path traversal attacks can read arbitrary files through ../ sequences.
/// 
/// Used by: /vulnerabilities/path-traversal
/// </summary>
[ApiController]
[Route("api/vulnerabilities/path-traversal")]
public class PathTraversalController : VulnerabilityDemoControllerBase
{
    private static readonly string DocumentsPath = Path.Combine(
        Directory.GetCurrentDirectory(), 
        "Documents"
    );

    public PathTraversalController(ILogger<PathTraversalController> logger) 
        : base(logger, "path-traversal")
    {
        // Ensure documents directory exists with sample files
        if (!Directory.Exists(DocumentsPath))
        {
            Directory.CreateDirectory(DocumentsPath);
            CreateSampleFiles();
        }
    }

    // VULNERABLE: Direct path concatenation without validation
    [HttpGet("download")]
    public IActionResult DownloadFile([FromQuery] string filename)
    {
        LogDemoActivity("DownloadFile", $"Attempting to download: {filename}");
        
        if (string.IsNullOrWhiteSpace(filename))
        {
            return BadRequest(new { success = false, message = "Filename is required" });
        }

        // VULNERABLE: User input directly concatenated to path
        var filePath = Path.Combine(DocumentsPath, filename);

        if (!System.IO.File.Exists(filePath))
        {
            return NotFound(new { success = false, message = "File not found" });
        }

        var fileContent = System.IO.File.ReadAllText(filePath);

        return Ok(new
        {
            success = true,
            requestedPath = filePath,
            filename = filename,
            content = fileContent
        });
    }

    private void CreateSampleFiles()
    {
        var files = new Dictionary<string, string>
        {
            ["report.pdf"] = "[PDF Binary Data]\nQuarterly Report Q4 2023\nConfidential - For Internal Use Only\n\nRevenue: $5.2M\nProfit: $1.8M",
            ["invoice.docx"] = "[DOCX Binary Data]\nInvoice #12345\nDate: 2024-01-15\nAmount: $1,299.00\nCustomer: Acme Corp",
            ["readme.txt"] = "Welcome to the document system!\n\nAvailable files:\n- report.pdf\n- invoice.docx\n- presentation.pptx"
        };

        foreach (var file in files)
        {
            System.IO.File.WriteAllText(
                Path.Combine(DocumentsPath, file.Key),
                file.Value
            );
        }
    }
}

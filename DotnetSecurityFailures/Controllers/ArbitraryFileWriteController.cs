using Microsoft.AspNetCore.Mvc;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating Arbitrary File Write vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how arbitrary file write attacks can write to any location on the filesystem.
/// 
/// Used by: /vulnerabilities/arbitrary-file-write
/// </summary>
[ApiController]
[Route("api/vulnerabilities/arbitrary-file-write")]
public class ArbitraryFileWriteController : VulnerabilityDemoControllerBase
{
    private readonly string _baseDirectory;

    public ArbitraryFileWriteController(
        ILogger<ArbitraryFileWriteController> logger,
        IWebHostEnvironment env) 
        : base(logger, "arbitrary-file-write")
    {
        _baseDirectory = Path.Combine(env.ContentRootPath, "Backups");
        Directory.CreateDirectory(_baseDirectory);
    }

    [HttpPost("save")]
    public IActionResult SaveBackup([FromBody] BackupRequest request)
    {
        LogDemoActivity("SaveBackup", $"Attempting to write file: {request.FileName}");
        
        if (string.IsNullOrWhiteSpace(request.FileName))
        {
            return BadRequest(new { success = false, message = "Filename is required" });
        }

        if (string.IsNullOrWhiteSpace(request.Content))
        {
            return BadRequest(new { success = false, message = "Content is required" });
        }

        try
        {
            // VULNERABLE: Direct path concatenation without validation
            var filePath = Path.Combine(_baseDirectory, request.FileName);
            
            System.IO.File.WriteAllText(filePath, request.Content);

            var actualPath = Path.GetFullPath(filePath);
            var isOutsideBase = !actualPath.StartsWith(
                Path.GetFullPath(_baseDirectory), 
                StringComparison.OrdinalIgnoreCase
            );

            return Ok(new
            {
                success = true,
                fileName = request.FileName,
                actualPath = actualPath,
                isVulnerable = isOutsideBase,
                message = isOutsideBase 
                    ? "ARBITRARY FILE WRITE SUCCESSFUL!" 
                    : "Backup saved successfully"
            });
        }
        catch (Exception ex)
        {
            return Ok(new
            {
                success = false,
                message = $"Error: {ex.Message}",
                fileName = request.FileName
            });
        }
    }

    public class BackupRequest
    {
        public string FileName { get; set; } = "";
        public string Content { get; set; } = "";
    }
}

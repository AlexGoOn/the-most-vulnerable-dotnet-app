using Microsoft.AspNetCore.Mvc;
using System.IO.Compression;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating Zip Slip vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how malicious ZIP archives can write files outside the extraction directory.
/// 
/// Used by: /vulnerabilities/zip-slip
/// </summary>
[ApiController]
[Route("api/zip")]
public class ZipSlipController : VulnerabilityDemoControllerBase
{
    private static readonly string ExtractDirectory = Path.Combine(
        Directory.GetCurrentDirectory(),
        "ExtractedZips"
    );

    public ZipSlipController(ILogger<ZipSlipController> logger) 
        : base(logger, "zip-slip")
    {
        Directory.CreateDirectory(ExtractDirectory);
    }

    [HttpPost("extract")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> ExtractZip([FromForm] IFormFile zipFile)
    {
        LogDemoActivity("ExtractZip", $"Extracting ZIP file: {zipFile?.FileName}");
        
        if (zipFile == null || zipFile.Length == 0)
        {
            return BadRequest(new { success = false, message = "No file provided" });
        }

        try
        {
            var tempZipPath = Path.GetTempFileName();
            using (var stream = new FileStream(tempZipPath, FileMode.Create))
            {
                await zipFile.CopyToAsync(stream);
            }

            var extractedFiles = new List<ExtractedFileInfo>();
            var warnings = new List<string>();

            using (var archive = ZipFile.OpenRead(tempZipPath))
            {
                var normalizedTargetDir = Path.GetFullPath(ExtractDirectory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;

                foreach (var entry in archive.Entries)
                {
                    if (string.IsNullOrEmpty(entry.Name))
                        continue;

                    // VULNERABLE: No validation before extraction
                    var fullPath = Path.GetFullPath(Path.Combine(ExtractDirectory, entry.FullName));

                    var isTraversal = !fullPath.StartsWith(
                        normalizedTargetDir,
                        StringComparison.OrdinalIgnoreCase);

                    extractedFiles.Add(new ExtractedFileInfo
                    {
                        EntryName = entry.FullName,
                        ResolvedPath = fullPath,
                        IsTraversal = isTraversal,
                        WasExtracted = false
                    });

                    // VULNERABLE: Extract file WITHOUT validation
                    try
                    {
                        var directoryPath = Path.GetDirectoryName(fullPath);
                        if (!string.IsNullOrEmpty(directoryPath) && !Directory.Exists(directoryPath))
                        {
                            Directory.CreateDirectory(directoryPath);
                        }

                        entry.ExtractToFile(fullPath, overwrite: true);
                        
                        extractedFiles[extractedFiles.Count - 1].WasExtracted = true;

                        if (isTraversal)
                        {
                            warnings.Add($"ZIP SLIP DETECTED: '{entry.FullName}' escapes target directory!");
                            warnings.Add($"Target: {normalizedTargetDir}");
                            warnings.Add($"Resolved to: {fullPath}");
                            warnings.Add($"FILE WAS WRITTEN TO DISK!");
                        }
                    }
                    catch (Exception ex)
                    {
                        warnings.Add($"Failed to extract '{entry.FullName}': {ex.Message}");
                    }
                }
            }

            if (System.IO.File.Exists(tempZipPath))
            {
                System.IO.File.Delete(tempZipPath);
            }

            return Ok(new
            {
                success = true,
                targetDirectory = ExtractDirectory,
                extractedFiles = extractedFiles,
                warnings = warnings,
                hasTraversal = warnings.Count > 0
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new
            {
                success = false,
                message = $"Extraction failed: {ex.Message}"
            });
        }
    }

    private class ExtractedFileInfo
    {
        public string EntryName { get; set; } = "";
        public string ResolvedPath { get; set; } = "";
        public bool IsTraversal { get; set; }
        public bool WasExtracted { get; set; }
    }
}

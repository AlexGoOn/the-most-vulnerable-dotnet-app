using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace DotnetSecurityFailures.Controllers;

[ApiController]
[Route("api/files")]
[IgnoreAntiforgeryToken] // INTENTIONALLY VULNERABLE: Demo controller bypasses CSRF protection
public class VulnerableFileUploadController : ControllerBase
{
    private static readonly string UploadDirectory = Path.Combine(Path.GetTempPath(), "DotnetSecurityFailures_Uploads");
    private static readonly Dictionary<string, UploadedFile> UploadedFiles = new();

    public VulnerableFileUploadController()
    {
        if (!Directory.Exists(UploadDirectory))
        {
            Directory.CreateDirectory(UploadDirectory);
        }
    }

    // VULNERABLE: Accepts any file without validation
    [HttpPost("upload")]
    public IActionResult Upload([FromBody] FileUploadRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Filename) || string.IsNullOrWhiteSpace(request.Content))
        {
            return BadRequest(new { success = false, message = "Filename and content are required" });
        }

        var fileId = Guid.NewGuid().ToString();
        var filePath = Path.Combine(UploadDirectory, fileId);

        // VULNERABLE: Save file with user-provided content without validation
        System.IO.File.WriteAllText(filePath, request.Content, Encoding.UTF8);

        var uploadedFile = new UploadedFile
        {
            Id = fileId,
            OriginalFilename = request.Filename,
            FilePath = filePath,
            UploadedAt = DateTime.UtcNow
        };

        UploadedFiles[fileId] = uploadedFile;

        return Ok(new
        {
            success = true,
            fileId = fileId,
            filename = request.Filename,
            viewUrl = $"/api/files/view/{fileId}"
        });
    }

    // VULNERABLE: Serves files without proper Content-Type validation
    [HttpGet("view/{fileId}")]
    public IActionResult ViewFile(string fileId)
    {
        if (!UploadedFiles.TryGetValue(fileId, out var uploadedFile))
        {
            return NotFound(new { success = false, message = "File not found" });
        }

        if (!System.IO.File.Exists(uploadedFile.FilePath))
        {
            return NotFound(new { success = false, message = "File not found on disk" });
        }

        var fileBytes = System.IO.File.ReadAllBytes(uploadedFile.FilePath);

        // VULNERABLE: Always serves as text/html without validation!
        // This allows XSS when HTML files with scripts are uploaded
        return File(fileBytes, "text/html");
    }

    public class FileUploadRequest
    {
        public string Filename { get; set; } = "";
        public string Content { get; set; } = "";
    }

    private class UploadedFile
    {
        public string Id { get; set; } = "";
        public string OriginalFilename { get; set; } = "";
        public string FilePath { get; set; } = "";
        public DateTime UploadedAt { get; set; }
    }
}

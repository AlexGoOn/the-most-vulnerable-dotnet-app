using Microsoft.AspNetCore.Mvc;
using System.Xml;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating XXE (XML External Entity) vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how XXE attacks can read local files and perform SSRF through external entities.
/// 
/// Used by: /vulnerabilities/xxe-injection
/// </summary>
[ApiController]
[Route("api/xxe")]
public class XxeInjectionController : VulnerabilityDemoControllerBase
{
    private readonly IWebHostEnvironment _environment;

    public XxeInjectionController(
        ILogger<XxeInjectionController> logger,
        IWebHostEnvironment environment) 
        : base(logger, "xxe-injection")
    {
        _environment = environment;
    }

    [HttpGet("secret-path")]
    public IActionResult GetSecretPath()
    {
        LogDemoActivity("GetSecretPath", "Providing secret file path for XXE demo");

        var secretFilePath = Path.Combine(_environment.WebRootPath, "secrets", "database_config.txt");
        var fileUrl = $"file:///{secretFilePath.Replace("\\", "/")}";
        //file:///C:/path/to/your/project/secrets/database_config.txt

        return Ok(new
        {
            SecretFilePath = secretFilePath,
            FileUrl = fileUrl
        });
    }

    [HttpPost("process-user")]
    public IActionResult ProcessUserXml([FromBody] XmlRequest request)
    {
        LogDemoActivity("ProcessUserXml", "Processing XML with XmlResolver enabled (VULNERABLE)");

        if (string.IsNullOrWhiteSpace(request.XmlContent))
        {
            return BadRequest(new { Success = false, Error = "XML content is required" });
        }

        try
        {
            // VULNERABLE: Explicitly enabling XmlResolver
            var doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver(); // DANGEROUS!
            doc.LoadXml(request.XmlContent);

            var name = doc.SelectSingleNode("//user/name")?.InnerText ?? "";
            var email = doc.SelectSingleNode("//user/email")?.InnerText ?? "";
            var bio = doc.SelectSingleNode("//user/bio")?.InnerText ?? "";

            // Check if XXE was exploited (file content in name field)
            if (!string.IsNullOrEmpty(name) && (name.Contains("connection") || name.Contains("password") || name.Length > 100))
            {
                return Ok(new
                {
                    Success = false,
                    Warning = $"XXE ATTACK SUCCESSFUL!\n\nFile contents extracted:\n{name}",
                    ProcessedData = new { Name = name, Email = email, Bio = bio }
                });
            }

            return Ok(new
            {
                Success = true,
                Message = "XML processed successfully",
                ProcessedData = new { Name = name, Email = email, Bio = bio }
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new
            {
                Success = false,
                Error = $"Failed to process XML: {ex.Message}"
            });
        }
    }

    [HttpPost("process-safe")]
    public IActionResult ProcessUserXmlSafe([FromBody] XmlRequest request)
    {
        LogDemoActivity("ProcessUserXmlSafe", "Processing XML with secure defaults");

        if (string.IsNullOrWhiteSpace(request.XmlContent))
        {
            return BadRequest(new { Success = false, Error = "XML content is required" });
        }

        try
        {
            // SAFE: XmlResolver is null by default in modern .NET
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit, // Explicitly prohibit DTD
                XmlResolver = null // Explicitly set to null
            };

            using var stringReader = new StringReader(request.XmlContent);
            using var xmlReader = XmlReader.Create(stringReader, settings);

            var doc = new XmlDocument();
            doc.Load(xmlReader);

            var name = doc.SelectSingleNode("//user/name")?.InnerText ?? "";
            var email = doc.SelectSingleNode("//user/email")?.InnerText ?? "";
            var bio = doc.SelectSingleNode("//user/bio")?.InnerText ?? "";

            return Ok(new
            {
                Success = true,
                Message = "? XML processed safely - DTD processing disabled",
                ProcessedData = new { Name = name, Email = email, Bio = bio }
            });
        }
        catch (XmlException ex)
        {
            return BadRequest(new
            {
                Success = false,
                Error = $"DTD processing is prohibited. XXE attack blocked! Details: {ex.Message}"
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new
            {
                Success = false,
                Error = $"Failed to process XML: {ex.Message}"
            });
        }
    }

    [HttpPost("parse")]
    public IActionResult ParseXml([FromBody] XmlRequest request)
    {
        LogDemoActivity("ParseXml", "Parsing XML with external entities enabled");
        
        if (string.IsNullOrWhiteSpace(request.XmlContent))
        {
            return BadRequest(new { success = false, message = "XML content is required" });
        }

        try
        {
            // VULNERABLE: XmlReaderSettings with DTD processing enabled
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse, // DANGEROUS!
                XmlResolver = new XmlUrlResolver() // DANGEROUS!
            };

            using var stringReader = new StringReader(request.XmlContent);
            using var xmlReader = XmlReader.Create(stringReader, settings);

            var doc = new XmlDocument();
            doc.Load(xmlReader);

            var parsedData = new Dictionary<string, string>();
            
            if (doc.DocumentElement != null)
            {
                foreach (XmlNode node in doc.DocumentElement.ChildNodes)
                {
                    if (node.NodeType == XmlNodeType.Element)
                    {
                        parsedData[node.Name] = node.InnerText;
                    }
                }
            }

            return Ok(new
            {
                success = true,
                parsedData = parsedData,
                warning = "XML parsed with external entities enabled (VULNERABLE!)"
            });
        }
        catch (Exception ex)
        {
            return Ok(new
            {
                success = false,
                message = $"Parsing failed: {ex.Message}",
                details = ex.ToString()
            });
        }
    }

    public class XmlRequest
    {
        public string XmlContent { get; set; } = "";
    }
}

using Microsoft.AspNetCore.Mvc;

namespace DotnetSecurityFailures.Controllers;

/// <summary>
/// Controller demonstrating Verbose Error Messages vulnerability
/// 
/// This controller contains INTENTIONALLY VULNERABLE code to demonstrate
/// how detailed error messages can leak sensitive information.
/// 
/// Used by: /vulnerabilities/verbose-errors
/// </summary>
[ApiController]
[Route("api/errors")]
public class VerboseErrorsController : VulnerabilityDemoControllerBase
{
    public VerboseErrorsController(ILogger<VerboseErrorsController> logger)
        : base(logger, "verbose-errors")
    {
    }

    [HttpGet("database")]
    public IActionResult DatabaseError([FromQuery] bool showVerbose = false)
    {
        LogDemoActivity("DatabaseError", $"Triggering database error (verbose: {showVerbose})");
        
        try
        {
            // VULNERABLE: Simulate database error with connection string exposed
            throw new InvalidOperationException(
                "Database connection failed. " +
                "Login failed for user 'sa'. " +
                "Connection string: Server=prod-db-01.internal.company.com;Database=ProductionDB;User ID=sa;Password=SuperSecret123!; " +
                "at System.Data.SqlClient.SqlInternalConnection.OnError(SqlException exception, Boolean breakConnection) " +
                "at System.Data.SqlClient.TdsParser.ThrowExceptionAndWarning(TdsParserStateObject stateObj)"
            );
        }
        catch (Exception ex)
        {
            if (showVerbose)
            {
                // DANGEROUS: Return full exception details to client
                return StatusCode(500, new
                {
                    error = "Database Error",
                    message = ex.Message,
                    stackTrace = ex.StackTrace,
                    type = ex.GetType().FullName,
                    source = ex.Source,
                    server = "prod-db-01.internal.company.com",
                    database = "ProductionDB",
                    connectionString = "Server=prod-db-01.internal.company.com;Database=ProductionDB;User ID=sa;Password=SuperSecret123!"
                });
            }
            else
            {
                // SAFE: Generic error message
                var errorId = Guid.NewGuid().ToString("N")[..8];
                Logger.LogError(ex, "Database error occurred. ErrorId: {ErrorId}", errorId);
                
                return StatusCode(500, new
                {
                    error = "Unable to connect to database",
                    message = "Please try again later. If the problem persists, contact support.",
                    errorId
                });
            }
        }
    }

    [HttpGet("exception")]
    public IActionResult UnhandledException([FromQuery] bool showVerbose = false)
    {
        LogDemoActivity("UnhandledException", $"Triggering unhandled exception (verbose: {showVerbose})");
        
        try
        {
            // Simulate unhandled exception
            var path = @"C:\AppData\Production\config\database_passwords.txt";
            System.IO.File.ReadAllText(path);
            return Ok();
        }
        catch (Exception ex)
        {
            if (showVerbose)
            {
                // DANGEROUS: Exposes file paths and system details
                return StatusCode(500, new
                {
                    error = "Unhandled Exception",
                    message = ex.Message,
                    stackTrace = ex.StackTrace,
                    type = ex.GetType().FullName,
                    filePath = @"C:\AppData\Production\config\database_passwords.txt",
                    serverVersion = Environment.Version.ToString(),
                    machineName = Environment.MachineName,
                    osVersion = Environment.OSVersion.ToString(),
                    source = ex.Source
                });
            }
            else
            {
                // SAFE: Generic error message
                var errorId = Guid.NewGuid().ToString("N")[..8];
                Logger.LogError(ex, "Unhandled exception occurred. ErrorId: {ErrorId}", errorId);
                
                return StatusCode(500, new
                {
                    error = "An error occurred",
                    message = "The operation could not be completed. Please contact support if the issue persists.",
                    errorId
                });
            }
        }
    }

    [HttpPost("process")]
    public IActionResult ProcessData([FromBody] ProcessRequest request, [FromQuery] bool showVerbose = false)
    {
        LogDemoActivity("ProcessData", $"Processing: {request.Data} (verbose: {showVerbose})");
        
        try
        {
            if (string.IsNullOrEmpty(request.Data))
            {
                throw new ArgumentException("Data cannot be empty", nameof(request.Data));
            }

            // Simulate processing error
            throw new InvalidOperationException(
                $"Failed to process data: '{request.Data}'. " +
                $"Internal service URL: http://internal-api.company.local:8080/process. " +
                $"API Key: sk_prod_abc123xyz789. " +
                $"Database: ProductionDB on server SQLSERVER-PROD-01"
            );
        }
        catch (Exception ex)
        {
            if (showVerbose)
            {
                // DANGEROUS: Full exception details
                return StatusCode(500, new
                {
                    success = false,
                    error = ex.GetType().Name,
                    message = ex.Message,
                    stackTrace = ex.StackTrace,
                    innerException = ex.InnerException?.Message,
                    data = ex.Data,
                    helpLink = ex.HelpLink,
                    source = ex.Source,
                    targetSite = ex.TargetSite?.ToString()
                });
            }
            else
            {
                // SAFE: Generic error message
                var errorId = Guid.NewGuid().ToString("N")[..8];
                Logger.LogError(ex, "Processing error occurred. ErrorId: {ErrorId}", errorId);
                
                return StatusCode(500, new
                {
                    success = false,
                    error = "Processing failed",
                    message = "Unable to process your request. Please try again later.",
                    errorId
                });
            }
        }
    }

    public class ProcessRequest
    {
        public string Data { get; set; } = "";
    }
}

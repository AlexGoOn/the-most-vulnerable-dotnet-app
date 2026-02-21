using System.Diagnostics;
using System.Runtime.InteropServices;

namespace DotnetSecurityFailures.Services;

public class VulnerableCommandService
{
    public string GetExecutedCommand(string userInput)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return $"cmd.exe /c echo Processing: {userInput}";
        }
        else
        {
            return $"/bin/sh -c \"echo Processing: {userInput}\"";
        }
    }

    // VULNERABLE CODE - for demonstration purposes
    public string ExecuteCommandVulnerable(string userInput)
    {
        try
        {
            var processInfo = new ProcessStartInfo
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                processInfo.FileName = "cmd.exe";
                processInfo.Arguments = $"/c echo Processing: {userInput}";
            }
            else
            {
                processInfo.FileName = "/bin/sh";
                processInfo.Arguments = $"-c \"echo Processing: {userInput}\"";
            }

            using var process = Process.Start(processInfo);
            if (process == null)
            {
                return "ERROR: Failed to start process";
            }

            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            var result = string.Empty;
            
            if (!string.IsNullOrEmpty(output))
            {
                result += output;
            }
            
            if (!string.IsNullOrEmpty(error))
            {
                if (!string.IsNullOrEmpty(result))
                    result += "\n\n";
                result += "Error:\n" + error;
            }

            if (string.IsNullOrEmpty(result))
            {
                result = "Command executed (no output)";
            }

            return result;
        }
        catch (Exception ex)
        {
            return $"ERROR: {ex.Message}\n\nException Type: {ex.GetType().Name}";
        }
    }

    // Safe implementation example
    public string ExecuteCommandSafe(string userInput)
    {
        // 1. Validate input - whitelist only alphanumeric and basic chars
        if (!System.Text.RegularExpressions.Regex.IsMatch(userInput, @"^[a-zA-Z0-9\s\.\-_]+$"))
        {
            throw new ArgumentException("Invalid input - only alphanumeric characters allowed");
        }

        // 2. Use ArgumentList instead of Arguments string
        var processInfo = new ProcessStartInfo
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            processInfo.FileName = "cmd.exe";
            // ArgumentList passes each argument separately
            processInfo.ArgumentList.Add("/c");
            processInfo.ArgumentList.Add("echo");
            processInfo.ArgumentList.Add("Processing:");
            processInfo.ArgumentList.Add(userInput);
        }
        else
        {
            processInfo.FileName = "/bin/sh";
            processInfo.ArgumentList.Add("-c");
            processInfo.ArgumentList.Add($"echo Processing: {userInput}");
        }

        using var process = Process.Start(processInfo);
        if (process == null)
        {
            return "ERROR: Failed to start process";
        }

        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();

        return !string.IsNullOrEmpty(output) ? output : 
               !string.IsNullOrEmpty(error) ? error : 
               "Command executed successfully";
    }
}

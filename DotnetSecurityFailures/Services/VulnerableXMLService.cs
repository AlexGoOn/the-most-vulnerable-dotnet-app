using System.Text;
using System.Xml;

namespace DotnetSecurityFailures.Services;

public class VulnerableXMLService
{
    // VULNERABLE: String concatenation in XML generation
    public XmlParseResult SaveProfileVulnerable(string fullName, string email, string bio)
    {
        try
        {
            // DANGEROUS: String concatenation allows XML injection
            string xmlString = $@"<user>
  <name>{fullName}</name>
  <email>{email}</email>
  <bio>{bio}</bio>
  <role>user</role>
  <balance>100</balance>
  <isAdmin>false</isAdmin>
</user>";

            // Parse the XML to demonstrate real parsing
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(xmlString);

            // Extract actual values from parsed XML
            var result = new XmlParseResult
            {
                OriginalXml = xmlString,
                Success = true
            };

            // Parse and extract values - this shows the real vulnerability
            var nameNode = doc.SelectSingleNode("//name");
            var emailNode = doc.SelectSingleNode("//email");
            var bioNode = doc.SelectSingleNode("//bio");
            var roleNodes = doc.SelectNodes("//role");
            var balanceNodes = doc.SelectNodes("//balance");
            var isAdminNodes = doc.SelectNodes("//isAdmin");

            result.ParsedName = nameNode?.InnerText ?? "";
            result.ParsedEmail = emailNode?.InnerText ?? "";
            result.ParsedBio = bioNode?.InnerText ?? "";

            // Check for injected elements
            if (roleNodes != null && roleNodes.Count > 0)
            {
                // Get first role node (injected one comes first!)
                result.ParsedRole = roleNodes[0]?.InnerText ?? "user";
                
                if (roleNodes.Count > 1)
                {
                    result.InjectionDetected = true;
                    result.InjectedElements.Add($"Multiple <role> tags found! Count: {roleNodes.Count}");
                    result.InjectedElements.Add($"First role (USED BY SYSTEM): {roleNodes[0]?.InnerText}");
                    result.InjectedElements.Add($"Original role (IGNORED): {roleNodes[roleNodes.Count - 1]?.InnerText}");
                }
            }

            if (balanceNodes != null && balanceNodes.Count > 0)
            {
                result.ParsedBalance = balanceNodes[0]?.InnerText ?? "100";
                
                if (balanceNodes.Count > 1 || result.ParsedBalance != "100")
                {
                    result.InjectionDetected = true;
                    result.InjectedElements.Add($"Balance manipulation detected!");
                    result.InjectedElements.Add($"First balance (USED BY SYSTEM): {balanceNodes[0]?.InnerText}");
                    if (balanceNodes.Count > 1)
                    {
                        result.InjectedElements.Add($"Original balance (IGNORED): {balanceNodes[balanceNodes.Count - 1]?.InnerText}");
                    }
                }
            }

            if (isAdminNodes != null && isAdminNodes.Count > 0)
            {
                result.ParsedIsAdmin = isAdminNodes[0]?.InnerText ?? "false";
                
                if (isAdminNodes.Count > 1 || result.ParsedIsAdmin?.ToLower() == "true")
                {
                    result.InjectionDetected = true;
                    result.InjectedElements.Add($"Admin flag manipulation detected!");
                    result.InjectedElements.Add($"First isAdmin (USED BY SYSTEM): {isAdminNodes[0]?.InnerText}");
                    if (isAdminNodes.Count > 1)
                    {
                        result.InjectedElements.Add($"Original isAdmin (IGNORED): {isAdminNodes[isAdminNodes.Count - 1]?.InnerText}");
                    }
                }
            }

            // Build analysis
            result.Analysis = BuildAnalysis(result);

            return result;
        }
        catch (XmlException ex)
        {
            return new XmlParseResult
            {
                Success = false,
                ErrorMessage = $"XML parsing error: {ex.Message}\n\nMalformed XML injection attempt detected!",
                OriginalXml = $@"<user>
  <name>{fullName}</name>
  <email>{email}</email>
  <bio>{bio}</bio>
  <role>user</role>
  <balance>100</balance>
  <isAdmin>false</isAdmin>
</user>"
            };
        }
    }

    // SAFE: Using XmlDocument API with proper escaping
    public XmlParseResult SaveProfileSafe(string fullName, string email, string bio)
    {
        try
        {
            XmlDocument doc = new XmlDocument();
            XmlElement userElement = doc.CreateElement("user");

            XmlElement nameElement = doc.CreateElement("name");
            nameElement.InnerText = fullName; // Automatically escaped
            userElement.AppendChild(nameElement);

            XmlElement emailElement = doc.CreateElement("email");
            emailElement.InnerText = email;
            userElement.AppendChild(emailElement);

            XmlElement bioElement = doc.CreateElement("bio");
            bioElement.InnerText = bio;
            userElement.AppendChild(bioElement);

            XmlElement roleElement = doc.CreateElement("role");
            roleElement.InnerText = "user";
            userElement.AppendChild(roleElement);

            XmlElement balanceElement = doc.CreateElement("balance");
            balanceElement.InnerText = "100";
            userElement.AppendChild(balanceElement);

            XmlElement isAdminElement = doc.CreateElement("isAdmin");
            isAdminElement.InnerText = "false";
            userElement.AppendChild(isAdminElement);

            doc.AppendChild(userElement);

            // Get formatted XML
            var stringWriter = new StringWriter();
            var xmlWriter = XmlWriter.Create(stringWriter, new XmlWriterSettings { Indent = true });
            doc.Save(xmlWriter);
            string xmlString = stringWriter.ToString();

            var result = new XmlParseResult
            {
                OriginalXml = xmlString,
                Success = true,
                ParsedName = fullName,
                ParsedEmail = email,
                ParsedBio = bio,
                ParsedRole = "user",
                ParsedBalance = "100",
                ParsedIsAdmin = "false",
                InjectionDetected = false
            };

            result.Analysis = "XML generated safely using XmlDocument API.\nAll special characters automatically escaped.\nInjection attempts treated as literal text.";

            return result;
        }
        catch (Exception ex)
        {
            return new XmlParseResult
            {
                Success = false,
                ErrorMessage = $"Error: {ex.Message}"
            };
        }
    }

    private string BuildAnalysis(XmlParseResult result)
    {
        var analysis = new StringBuilder();

        if (!result.InjectionDetected)
        {
            analysis.AppendLine("Profile saved successfully!");
            analysis.AppendLine();
            analysis.AppendLine($"Name: {result.ParsedName}");
            analysis.AppendLine($"Email: {result.ParsedEmail}");
            analysis.AppendLine($"Bio: {result.ParsedBio}");
            analysis.AppendLine($"Role: {result.ParsedRole}");
            analysis.AppendLine($"Balance: {result.ParsedBalance}");
            analysis.AppendLine($"IsAdmin: {result.ParsedIsAdmin}");
            return analysis.ToString();
        }
        analysis.AppendLine();

        foreach (var injection in result.InjectedElements)
        {
            analysis.AppendLine($"  - {injection}");
        }

        analysis.AppendLine();
        analysis.AppendLine("IMPACT:");

        if (result.ParsedRole?.ToLower() == "admin")
        {
            analysis.AppendLine("  PRIVILEGE ESCALATION SUCCESSFUL!");
            analysis.AppendLine("  - User role changed from 'user' to 'admin'");
            analysis.AppendLine("  - Full administrative privileges granted");
            analysis.AppendLine("  - All system resources accessible");
        }

        if (result.ParsedBalance != "100")
        {
            analysis.AppendLine("  DATA MANIPULATION SUCCESSFUL!");
            analysis.AppendLine($"  - Account balance changed from 100 to {result.ParsedBalance}");
            analysis.AppendLine("  - Financial fraud achieved");
            analysis.AppendLine("  - Business logic bypassed");
        }

        if (result.ParsedIsAdmin?.ToLower() == "true")
        {
            analysis.AppendLine("  AUTHENTICATION BYPASS SUCCESSFUL!");
            analysis.AppendLine("  - Admin flag changed from 'false' to 'true'");
            analysis.AppendLine("  - Security controls bypassed");
            analysis.AppendLine("  - System-level access granted");
        }

        return analysis.ToString();
    }

    public string GetGeneratedXml(string fullName, string email, string bio)
    {
        return $@"<user>
  <name>{fullName}</name>
  <email>{email}</email>
  <bio>{bio}</bio>
  <role>user</role>
  <balance>100</balance>
  <isAdmin>false</isAdmin>
</user>";
    }
}

public class UserProfile
{
    public int Id { get; set; }
    public string Name { get; set; } = "";
    public string Email { get; set; } = "";
    public string Bio { get; set; } = "";
    public string Role { get; set; } = "user";
    public int Balance { get; set; }
    public bool IsAdmin { get; set; }
}

public class XmlParseResult
{
    public string OriginalXml { get; set; } = "";
    public bool Success { get; set; }
    public string? ErrorMessage { get; set; }
    public string ParsedName { get; set; } = "";
    public string ParsedEmail { get; set; } = "";
    public string ParsedBio { get; set; } = "";
    public string ParsedRole { get; set; } = "user";
    public string ParsedBalance { get; set; } = "100";
    public string ParsedIsAdmin { get; set; } = "false";
    public bool InjectionDetected { get; set; }
    public List<string> InjectedElements { get; set; } = new();
    public string Analysis { get; set; } = "";
}

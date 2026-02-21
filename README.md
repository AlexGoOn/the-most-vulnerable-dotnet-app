# .NET Security Vulnerabilities - Educational Application

 This application contains intentionally vulnerable code for educational purposes only!

This is an interactive educational project that demonstrates common security vulnerabilities in .NET applications. Each vulnerability is reproduced in a real working .NET environment where you can debug, explore, and understand what NOT to do, along with recommended secure practices.

## Learning Process

- **Learn by Example**: See real vulnerable code in action
- **Debug and Explore**: Step through vulnerable code paths
- **Learn Best Practices**: Each example includes secure alternatives
- **CWE (Common Weakness Enumeration) References**: Every vulnerability links to official CWE documentation for pro insights

## Vulnerability Categories

### Injection Attacks

- **[SQL Injection](Components/Pages/SqlInjection.razor)** (CWE-89)  
  Executing arbitrary SQL commands through string concatenation in queries
  
- **[Command Injection](Components/Pages/CommandInjection.razor)** (CWE-78)  
  Executing system commands via Process.Start with user input
  
- **[Code Injection (CSharpScript)](Components/Pages/CodeInjectionCSharpScript.razor)** (CWE-94)  
  Executing arbitrary C# code through dynamic script evaluation
  
- **[Template Injection](Components/Pages/TemplateInjection.razor)** (CWE-1336)  
  Injecting code into template engines (Razor, etc.)

- **[LDAP Injection](Components/Pages/LdapInjection.razor)** (CWE-90)  
  Manipulating LDAP queries through unsafe search filters
  
- **[XPath Injection](Components/Pages/XpathInjection.razor)** (CWE-643)  
  Manipulating XPath queries to XML documents
  
- **[XML Injection](Components/Pages/XmlInjection.razor)** (CWE-91)  
  Injecting malicious XML content

- **[CRLF Injection](Components/Pages/CrlfInjection.razor)** (CWE-93)  
  Injecting carriage return and line feed characters
  
- **[Expression Language Injection (Dynamic LINQ)](Components/Pages/ExpressionInjection.razor)** (CWE-917)  
  Injecting code into dynamic LINQ expressions
  
- **[JSON Injection](Components/Pages/JsonInjection.razor)** (CWE-91)  
  Manipulating JSON serialization/deserialization
  
- **[Log Injection (Log Forging)](Components/Pages/LogInjection.razor)** (CWE-117)  
  Injecting malicious data into logs through improper sanitization

---

### Cross-Site Scripting (XSS)

- **[Stored XSS](Components/Pages/StoredXss.razor)** (CWE-79)  
  Storing and displaying HTML content from database without sanitization

- **[Reflected XSS](Components/Pages/ReflectedXss.razor)** (CWE-79)  
  Displaying URL parameters without escaping in HTML
  
- **[XSS With JS Interop](Components/Pages/DomBasedXss.razor)** (CWE-79)  
  Client-side JavaScript manipulation with user input
  
- **[XSS via Attributes](Components/Pages/XssAttributes.razor)** (CWE-79)  
  Injecting malicious code into HTML attributes
  
- **[XSS via SVG](Components/Pages/XssSvg.razor)** (CWE-79)  
  Embedding JavaScript in SVG files
  
- **[XSS via File Upload](Components/Pages/XssFileUpload.razor)** (CWE-79)  
  Uploading HTML files with malicious scripts

- **[XSS via CSS](Components/Pages/XssCss.razor)** (CWE-79)  
  Using CSS expressions for code execution

---

### Authentication & Authorization

- **[Hardcoded Credentials](Components/Pages/HardcodedCredentials.razor)** (CWE-798)  
  Usernames and passwords hardcoded in source code
  
- **[Missing Authorization Check](Components/Pages/MissingAuthorization.razor)** (CWE-862)  
  API endpoints accessible without authorization checks
  
- **[Broken JWT Implementation](Components/Pages/BrokenJwt.razor)** (CWE-347)  
  JWT without signature validation
  
- **[Privilege Escalation](Components/Pages/PrivilegeEscalation.razor)** (CWE-269)  
  Modifying user role through form field

- **[Insecure Direct Object Reference (IDOR)](Components/Pages/Idor.razor)** (CWE-639)  
  Accessing other users' data by modifying ID parameters
  
- **[Password Reset Poisoning](Components/Pages/PasswordResetPoisoning.razor)** (CWE-640)  
  Host header injection in password reset

- **[Weak Password Requirements](Components/Pages/WeakPassword.razor)** (CWE-521)  
  Allowing weak passwords

---

### Cryptography Issues

- **[Weak Hashing (MD5/SHA1)](Components/Pages/WeakHashing.razor)** (CWE-327)  
  Using cryptographically weak hashing algorithms
  
- **[ECB Mode Encryption](Components/Pages/EcbMode.razor)** (CWE-327)  
  Using Electronic Codebook mode
  
- **[Insufficient Key Length](Components/Pages/InsufficientKeyLength.razor)** (CWE-326)  
  Using short encryption keys (DES, 3DES)
  
- **[No Salt in Password Hashing](Components/Pages/NoSaltHashing.razor)** (CWE-759)  
  Hashing passwords without unique salt

- **[Predictable Random Numbers](Components/Pages/WeakRandom.razor)** (CWE-338)  
  Using Random instead of cryptographically secure generator

- **[Improper Certificate Validation](Components/Pages/CertificateValidation.razor)** (CWE-295)  
  Disabling SSL certificate validation

---

### Sensitive Data Exposure

- **[API Keys Exposure](Components/Pages/ApiKeysExposure.razor)** (CWE-798)  
  Exposing API keys in client-side code

- **[Sensitive Data in Logs](Components/Pages/SensitiveDataLogs.razor)** (CWE-532)  
  Logging passwords, credit cards, tokens

- **[Verbose Error Messages](Components/Pages/VerboseErrors.razor)** (CWE-209)  
  Exposing stack traces and internal details
  
- **[Directory Listing](Components/Pages/DirectoryListing.razor)** (CWE-548)  
  Exposing directory contents
  
- **[Sensitive Data in URLs](Components/Pages/DataInUrls.razor)** (CWE-598)  
  Passing tokens/passwords in query strings

---

### XML & Serialization

- **[XXE (XML External Entity)](Components/Pages/XxeInjection.razor)** (CWE-611)  
  Processing untrusted XML with external entities
  
- **[Insecure Deserialization (BinaryFormatter)](Components/Pages/InsecureDeserialization.razor)** (CWE-502)  
  Using BinaryFormatter with untrusted data
  
- **[JSON Deserialization Attacks](Components/Pages/JsonDeserialization.razor)** (CWE-502)  
  Type name handling in JSON.NET
  
- **[Insecure YAML Deserialization](Components/Pages/YamlDeserialization.razor)** (CWE-502)  
  YAML deserialization vulnerabilities
- **[XML Bomb (Billion Laughs)](Components/Pages/XmlBomb.razor)** (CWE-776)  
  Exponential entity expansion attack

---

### File Operations

- **[Path Traversal](Components/Pages/PathTraversal.razor)** (CWE-22)  
  Reading arbitrary files through path manipulation (../)
  
- **[Arbitrary File Write](Components/Pages/ArbitraryFileWrite.razor)** (CWE-73)  
  Writing to arbitrary file locations

- **[Zip Slip](Components/Pages/ZipSlip.razor)** (CWE-22)  
  Archive extraction with path traversal

---

### Server-Side Request Forgery

- **[Basic SSRF](Components/Pages/BasicSsrf.razor)** (CWE-918)  
  Fetching URLs provided by user

- **[SSRF via File Upload](Components/Pages/SsrfFileUpload.razor)** (CWE-918)  
  Processing files with external references

---

### Business Logic Flaws

- **[Mass Assignment](Components/Pages/MassAssignment.razor)** (CWE-915)  
  Over-posting attack on model binding

- **[Negative Quantities](Components/Pages/NegativeQuantities.razor)** (CWE-20)  
  Accepting negative numbers in business logic
  
- **[Integer Overflow](Components/Pages/IntegerOverflow.razor)** (CWE-190)  
  Arithmetic operations causing overflow

---

### API Security

- **[Missing Rate Limiting](Components/Pages/MissingRateLimiting.razor)** (CWE-799)  
  APIs without throttling
  
- **[CORS Misconfiguration](Components/Pages/CorsMisconfiguration.razor)** (CWE-942)  
  Overly permissive CORS policy
  
- **[CSRF (Cross-Site Request Forgery)](Components/Pages/Csrf.razor)** (CWE-352)  
  Executing unauthorized actions on behalf of authenticated users

- **[Excessive Data Exposure](Components/Pages/ExcessiveDataExposure.razor)** (CWE-213)  
  Returning more data than needed

---

## Project Structure

```
DotnetSecurityFailures/
├── Components/
│   ├── Pages/              # Blazor pages demonstrating vulnerabilities
│   ├── Layout/             # Layout components
│   └── Shared/             # Shared components
├── Controllers/            # API controllers with vulnerable endpoints
├── Services/               # Vulnerable service implementations
├── Models/                 # Data models and enums
├── AttackerSite/          # HTML files for attack demonstrations
└── Program.cs             # Application startup configuration
```

## How to Use This Project

1. **Browse the Categories**: Start from the home page and explore vulnerabilities by category
2. **Read the Description**: Each page explains the vulnerability and its impact
3. **Try the Attack**: Use the provided attack payloads to see the vulnerability in action
4. **Debug the Code**: Set breakpoints and step through the vulnerable code
5. **Study the Fix**: Review the secure implementation recommendations
6. **Check CWE Links**: Follow the CWE links for comprehensive security knowledge


## Educational Value

This project is designed for:
- .NET developers learning secure coding
- Security trainers and educators
- Penetration testers understanding .NET vulnerabilities
- Students studying application security

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/dotnet/standard/security/)

## Contributing

This is an educational project. If you'd like to add more examples or enhance them, contributions are welcome!

---

**Remember**: The only way to truly understand security vulnerabilities is to see them in action. This project provides a safe, controlled environment to do exactly that. Happy learning!

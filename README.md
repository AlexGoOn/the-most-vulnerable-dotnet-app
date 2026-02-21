# The Most Vulnerable .NET App - Educational Project

This application contains intentionally vulnerable code for educational purposes only!
 
![Demo Image](DemoImage.png) 

This is an interactive educational project that demonstrates common security vulnerabilities in .NET applications. Each vulnerability is reproduced in a real working .NET environment where you can debug, explore, and understand what NOT to do, along with recommended secure practices.

## Learning Process

- **Learn by Example**: See real vulnerable code in action
- **Debug and Explore**: Step through vulnerable code paths
- **Learn Best Practices**: Each example includes secure alternatives
- **CWE (Common Weakness Enumeration) References**: Every vulnerability links to official CWE documentation for pro insights

## Vulnerability Categories

### Injection Attacks

- **[SQL Injection](DotnetSecurityFailures/Components/Pages/SqlInjection.razor)** (CWE-89)  
  Executing arbitrary SQL commands through string concatenation in queries
  
- **[Command Injection](DotnetSecurityFailures/Components/Pages/CommandInjection.razor)** (CWE-78)  
  Executing system commands via Process.Start with user input
  
- **[Code Injection (CSharpScript)](DotnetSecurityFailures/Components/Pages/CodeInjectionCSharpScript.razor)** (CWE-94)  
  Executing arbitrary C# code through dynamic script evaluation
  
- **[Template Injection](DotnetSecurityFailures/Components/Pages/TemplateInjection.razor)** (CWE-1336)  
  Injecting code into template engines (Razor, etc.)

- **[LDAP Injection](DotnetSecurityFailures/Components/Pages/LdapInjection.razor)** (CWE-90)  
  Manipulating LDAP queries through unsafe search filters
  
- **[XPath Injection](DotnetSecurityFailures/Components/Pages/XpathInjection.razor)** (CWE-643)  
  Manipulating XPath queries to XML documents
  
- **[XML Injection](DotnetSecurityFailures/Components/Pages/XmlInjection.razor)** (CWE-91)  
  Injecting malicious XML content

- **[CRLF Injection](DotnetSecurityFailures/Components/Pages/CrlfInjection.razor)** (CWE-93)  
  Injecting carriage return and line feed characters
  
- **[Expression Language Injection (Dynamic LINQ)](DotnetSecurityFailures/Components/Pages/ExpressionInjection.razor)** (CWE-917)  
  Injecting code into dynamic LINQ expressions
  
- **[JSON Injection](DotnetSecurityFailures/Components/Pages/JsonInjection.razor)** (CWE-91)  
  Manipulating JSON serialization/deserialization
  
- **[Log Injection (Log Forging)](DotnetSecurityFailures/Components/Pages/LogInjection.razor)** (CWE-117)  
  Injecting malicious data into logs through improper sanitization

---

### Cross-Site Scripting (XSS)

- **[Stored XSS](DotnetSecurityFailures/Components/Pages/StoredXss.razor)** (CWE-79)  
  Storing and displaying HTML content from database without sanitization

- **[Reflected XSS](DotnetSecurityFailures/Components/Pages/ReflectedXss.razor)** (CWE-79)  
  Displaying URL parameters without escaping in HTML
  
- **[XSS With JS Interop](DotnetSecurityFailures/Components/Pages/DomBasedXss.razor)** (CWE-79)  
  Client-side JavaScript manipulation with user input
  
- **[XSS via Attributes](DotnetSecurityFailures/Components/Pages/XssAttributes.razor)** (CWE-79)  
  Injecting malicious code into HTML attributes
  
- **[XSS via SVG](DotnetSecurityFailures/Components/Pages/XssSvg.razor)** (CWE-79)  
  Embedding JavaScript in SVG files
  
- **[XSS via File Upload](DotnetSecurityFailures/Components/Pages/XssFileUpload.razor)** (CWE-79)  
  Uploading HTML files with malicious scripts

- **[XSS via CSS](DotnetSecurityFailures/Components/Pages/XssCss.razor)** (CWE-79)  
  Using CSS expressions for code execution

---

### Authentication & Authorization

- **[Hardcoded Credentials](DotnetSecurityFailures/Components/Pages/HardcodedCredentials.razor)** (CWE-798)  
  Usernames and passwords hardcoded in source code
  
- **[Missing Authorization Check](DotnetSecurityFailures/Components/Pages/MissingAuthorization.razor)** (CWE-862)  
  API endpoints accessible without authorization checks
  
- **[Broken JWT Implementation](DotnetSecurityFailures/Components/Pages/BrokenJwt.razor)** (CWE-347)  
  JWT without signature validation
  
- **[Privilege Escalation](DotnetSecurityFailures/Components/Pages/PrivilegeEscalation.razor)** (CWE-269)  
  Modifying user role through form field

- **[Insecure Direct Object Reference (IDOR)](DotnetSecurityFailures/Components/Pages/Idor.razor)** (CWE-639)  
  Accessing other users' data by modifying ID parameters
  
- **[Password Reset Poisoning](DotnetSecurityFailures/Components/Pages/PasswordResetPoisoning.razor)** (CWE-640)  
  Host header injection in password reset

- **[Weak Password Requirements](DotnetSecurityFailures/Components/Pages/WeakPassword.razor)** (CWE-521)  
  Allowing weak passwords

---

### Cryptography Issues

- **[Weak Hashing (MD5/SHA1)](DotnetSecurityFailures/Components/Pages/WeakHashing.razor)** (CWE-327)  
  Using cryptographically weak hashing algorithms
  
- **[ECB Mode Encryption](DotnetSecurityFailures/Components/Pages/EcbMode.razor)** (CWE-327)  
  Using Electronic Codebook mode
  
- **[Insufficient Key Length](DotnetSecurityFailures/Components/Pages/InsufficientKeyLength.razor)** (CWE-326)  
  Using short encryption keys (DES, 3DES)
  
- **[No Salt in Password Hashing](DotnetSecurityFailures/Components/Pages/NoSaltHashing.razor)** (CWE-759)  
  Hashing passwords without unique salt

- **[Predictable Random Numbers](DotnetSecurityFailures/Components/Pages/WeakRandom.razor)** (CWE-338)  
  Using Random instead of cryptographically secure generator

- **[Improper Certificate Validation](DotnetSecurityFailures/Components/Pages/CertificateValidation.razor)** (CWE-295)  
  Disabling SSL certificate validation

---

### Sensitive Data Exposure

- **[API Keys Exposure](DotnetSecurityFailures/Components/Pages/ApiKeysExposure.razor)** (CWE-798)  
  Exposing API keys in client-side code

- **[Sensitive Data in Logs](DotnetSecurityFailures/Components/Pages/SensitiveDataLogs.razor)** (CWE-532)  
  Logging passwords, credit cards, tokens

- **[Verbose Error Messages](DotnetSecurityFailures/Components/Pages/VerboseErrors.razor)** (CWE-209)  
  Exposing stack traces and internal details
  
- **[Directory Listing](DotnetSecurityFailures/Components/Pages/DirectoryListing.razor)** (CWE-548)  
  Exposing directory contents
  
- **[Sensitive Data in URLs](DotnetSecurityFailures/Components/Pages/DataInUrls.razor)** (CWE-598)  
  Passing tokens/passwords in query strings

---

### XML & Serialization

- **[XXE (XML External Entity)](DotnetSecurityFailures/Components/Pages/XxeInjection.razor)** (CWE-611)  
  Processing untrusted XML with external entities
  
- **[Insecure Deserialization (BinaryFormatter)](DotnetSecurityFailures/Components/Pages/InsecureDeserialization.razor)** (CWE-502)  
  Using BinaryFormatter with untrusted data
  
- **[JSON Deserialization Attacks](DotnetSecurityFailures/Components/Pages/JsonDeserialization.razor)** (CWE-502)  
  Type name handling in JSON.NET
  
- **[Insecure YAML Deserialization](DotnetSecurityFailures/Components/Pages/YamlDeserialization.razor)** (CWE-502)  
  YAML deserialization vulnerabilities
- **[XML Bomb (Billion Laughs)](DotnetSecurityFailures/Components/Pages/XmlBomb.razor)** (CWE-776)  
  Exponential entity expansion attack

---

### File Operations

- **[Path Traversal](DotnetSecurityFailures/Components/Pages/PathTraversal.razor)** (CWE-22)  
  Reading arbitrary files through path manipulation (../)
  
- **[Arbitrary File Write](DotnetSecurityFailures/Components/Pages/ArbitraryFileWrite.razor)** (CWE-73)  
  Writing to arbitrary file locations

- **[Zip Slip](DotnetSecurityFailures/Components/Pages/ZipSlip.razor)** (CWE-22)  
  Archive extraction with path traversal

---

### Server-Side Request Forgery

- **[Basic SSRF](DotnetSecurityFailures/Components/Pages/BasicSsrf.razor)** (CWE-918)  
  Fetching URLs provided by user

- **[SSRF via File Upload](DotnetSecurityFailures/Components/Pages/SsrfFileUpload.razor)** (CWE-918)  
  Processing files with external references

---

### Business Logic Flaws

- **[Mass Assignment](DotnetSecurityFailures/Components/Pages/MassAssignment.razor)** (CWE-915)  
  Over-posting attack on model binding

- **[Negative Quantities](DotnetSecurityFailures/Components/Pages/NegativeQuantities.razor)** (CWE-20)  
  Accepting negative numbers in business logic
  
- **[Integer Overflow](DotnetSecurityFailures/Components/Pages/IntegerOverflow.razor)** (CWE-190)  
  Arithmetic operations causing overflow

---

### API Security

- **[Missing Rate Limiting](DotnetSecurityFailures/Components/Pages/MissingRateLimiting.razor)** (CWE-799)  
  APIs without throttling
  
- **[CORS Misconfiguration](DotnetSecurityFailures/Components/Pages/CorsMisconfiguration.razor)** (CWE-942)  
  Overly permissive CORS policy
  
- **[CSRF (Cross-Site Request Forgery)](DotnetSecurityFailures/Components/Pages/Csrf.razor)** (CWE-352)  
  Executing unauthorized actions on behalf of authenticated users

- **[Excessive Data Exposure](DotnetSecurityFailures/Components/Pages/ExcessiveDataExposure.razor)** (CWE-213)  
  Returning more data than needed

---

## How to Use This Project

1. **Browse the Categories**: Start from the home page and explore vulnerabilities by category
2. **Read the Description**: Each page explains the vulnerability and its impact
3. **Try the Attack**: Use the provided attack payloads to see the vulnerability in action
4. **Debug the Code**: Set breakpoints and step through the vulnerable code
5. **Study the Fix**: Review the secure implementation recommendations
6. **Check CWE Links**: Follow the CWE links for comprehensive security knowledge


## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Microsoft Security Documentation](https://docs.microsoft.com/en-us/dotnet/standard/security/)

## Contributing

This is an educational project. If you'd like to add more examples or enhance them, contributions are welcome!

---

**Remember**: The only way to truly understand security vulnerabilities is to see them in action. This project provides a safe, controlled environment to do exactly that. Happy learning!

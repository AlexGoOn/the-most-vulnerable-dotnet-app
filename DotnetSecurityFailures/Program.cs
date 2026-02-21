using Brism;
using DotnetSecurityFailures.Components;
using DotnetSecurityFailures.Services;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.FileProviders;
using System.Security.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Core services
builder.Services.AddSingleton<VulnerabilityService>();
builder.Services.AddScoped<VulnerableDatabaseService>();
builder.Services.AddScoped<VulnerableCommandService>();
builder.Services.AddScoped<VulnerableLdapService>();
builder.Services.AddScoped<VulnerableNoSQLService>();
builder.Services.AddScoped<VulnerableXMLService>();

// Add controllers for API endpoints
builder.Services.AddControllers();
builder.Services.AddHttpClient();

// Code highlighting
builder.Services.AddBrism();

// Enable directory browsing (for vulnerability demonstration)
builder.Services.AddDirectoryBrowser();

// VULNERABLE CORS Configuration for demonstration
builder.Services.AddCors(options =>
{
    // DANGEROUS: Reflects any origin with credentials
    options.AddPolicy("VulnerablePolicy", policy =>
    {
        policy
            .SetIsOriginAllowed(_ => true) // CRITICAL: Allows ALL origins!
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials(); // With credentials = VERY DANGEROUS!
    });
    
    // Safe example: Public API without credentials
    options.AddPolicy("PublicAPI", policy =>
    {
        policy
            .AllowAnyOrigin() // Safe without credentials
            .WithMethods("GET")
            .WithHeaders("Content-Type");
        // Note: No .AllowCredentials() - this is safe
    });
});

// Add HttpClient for Blazor components
builder.Services.AddScoped(sp => 
{
    var navigationManager = sp.GetRequiredService<NavigationManager>();
    return new HttpClient { BaseAddress = new Uri(navigationManager.BaseUri) };
});

// Configure Kestrel to listen on THREE ports
// Port 7124 (HTTPS) - Main application
// Port 5001 (HTTP) - Attacker site for CORS/CSRF demo
// Port 5003 (HTTP) - Internal admin panel for SSRF demo
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(7124, listenOptions =>
    {
        listenOptions.UseHttps();
    });
    
    options.ListenLocalhost(5001); // HTTP - attacker site (CORS/CSRF)
    
    options.ListenLocalhost(5003); // HTTP - internal admin (SSRF target)
});

var app = builder.Build();

// CORS DEMO: Serve attacker page on port 5001 and admin panel on port 5003
var attackerPath = Path.Combine(builder.Environment.ContentRootPath, "AttackerSite");
app.Use(async (context, next) =>
{
    // Intercept port 5001 requests for attacker site
    if (context.Request.Host.Port == 5001)
    {
        if (context.Request.Path == "/")
        {
            // Serve CORS attacker page
            context.Response.ContentType = "text/html";
            var attackerHtml = Path.Combine(attackerPath, "attacker.html");
            if (File.Exists(attackerHtml))
            {
                await context.Response.SendFileAsync(attackerHtml);
                return;
            }
            else
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsync("Attacker page not found. Make sure AttackerSite/attacker.html exists.");
                return;
            }
        }
        else if (context.Request.Path.StartsWithSegments("/csrf"))
        {
            // Serve CSRF attacker page
            context.Response.ContentType = "text/html";
            var csrfAttackerHtml = Path.Combine(attackerPath, "csrf-attacker.html");
            if (File.Exists(csrfAttackerHtml))
            {
                await context.Response.SendFileAsync(csrfAttackerHtml);
                return;
            }
            else
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsync("CSRF attacker page not found. Make sure AttackerSite/csrf-attacker.html exists.");
                return;
            }
        }
    }
    
    // Intercept port 5003 requests for internal admin panel (SSRF target)
    if (context.Request.Host.Port == 5003)
    {
        context.Response.ContentType = "text/html";
        var adminHtml = Path.Combine(attackerPath, "ssrf-admin.html");
        if (File.Exists(adminHtml))
        {
            await context.Response.SendFileAsync(adminHtml);
            return;
        }
        else
        {
            context.Response.StatusCode = 404;
            await context.Response.WriteAsync("SSRF admin panel not found. Make sure AttackerSite/ssrf-admin.html exists.");
            return;
        }
    }
    
    await next();
});

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);

// Don't redirect HTTP to HTTPS - we need HTTP port 5001 for CORS demo
// app.UseHttpsRedirection();

// IMPORTANT: Enable CORS before other middleware
// Apply the vulnerable policy globally for demonstration
app.UseCors("VulnerablePolicy");

app.UseAntiforgery();

app.MapStaticAssets();

// VULNERABLE: Directory browsing enabled for uploads folder
var uploadsPath = Path.Combine(builder.Environment.WebRootPath, "uploads");
Directory.CreateDirectory(uploadsPath);
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(uploadsPath),
    RequestPath = "/uploads"
});
app.UseDirectoryBrowser(new DirectoryBrowserOptions
{
    FileProvider = new PhysicalFileProvider(uploadsPath),
    RequestPath = "/uploads"
});

// VULNERABLE: Directory browsing enabled for logs folder
var logsPath = Path.Combine(builder.Environment.WebRootPath, "logs");
Directory.CreateDirectory(logsPath);
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(logsPath),
    RequestPath = "/logs"
});
app.UseDirectoryBrowser(new DirectoryBrowserOptions
{
    FileProvider = new PhysicalFileProvider(logsPath),
    RequestPath = "/logs"
});

// Serve attacker's site static files
if (Directory.Exists(attackerPath))
{
    app.UseStaticFiles(new StaticFileOptions
    {
        FileProvider = new PhysicalFileProvider(attackerPath),
        RequestPath = "/attacker-site"
    });
}

// Map API controllers
app.MapControllers();

// Map Blazor components (only on port 7124)
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

Console.WriteLine("══════════════════════════════════════════════════════════════");
Console.WriteLine("│  .NET Security Vulnerabilities Demo                       │");
Console.WriteLine("══════════════════════════════════════════════════════════════");
Console.WriteLine();
Console.WriteLine("Main application:    https://localhost:7124");
Console.WriteLine("Attacker's site:     http://localhost:5001");
Console.WriteLine("Internal admin:      http://localhost:5003 (SSRF target)");
Console.WriteLine();
Console.WriteLine("Different ports + protocols = Different origins!");
Console.WriteLine("This enables real CORS and SSRF attack demonstrations.");
Console.WriteLine();
Console.WriteLine("VULNERABLE CORS Policy: SetIsOriginAllowed(_ => true)");
Console.WriteLine("This allows ANY origin with credentials!");
Console.WriteLine();
Console.WriteLine("Port 5003 simulates an internal admin panel that should");
Console.WriteLine("NEVER be accessible from the internet, but can be reached");
Console.WriteLine("via SSRF vulnerability from the main application.");
Console.WriteLine();

app.Run();

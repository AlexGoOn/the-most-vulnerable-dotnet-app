using Microsoft.AspNetCore.Mvc;
using DotnetSecurityFailures.Models;

namespace DotnetSecurityFailures.Controllers;

[ApiController]
[Route("api/public")]
public class PublicApiController : ControllerBase
{
    [HttpGet("products")]
    public IActionResult GetProducts()
    {
        var products = new List<Product>
        {
            new() { Id = 1, Name = "Laptop", Price = 999 },
            new() { Id = 2, Name = "Mouse", Price = 29 }
        };
        
        return Ok(products);
    }
}

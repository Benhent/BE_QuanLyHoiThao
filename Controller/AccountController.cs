using Appwrite;
using Appwrite.Services;
using Appwrite.Models;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;

[ApiController]
[Route("api/[controller]")]
public class AccountController : ControllerBase
{
    private readonly Client _client;

    public AccountController(IConfiguration config)
    {
        _client = new Client()
            .SetEndpoint(config["Appwrite:Api_Endpoint"])
            .SetProject(config["Appwrite:Project_Id"])
            .SetKey(config["Appwrite:Api_Key"]);
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        // Validate required fields
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password) || string.IsNullOrWhiteSpace(request.Name) || string.IsNullOrWhiteSpace(request.Phone))
        {
            return BadRequest(new { message = "All fields are required." });
        }

        // Validate Phone format
        if (!Regex.IsMatch(request.Phone, @"^\+\d{8,}$"))
        {
            return BadRequest(new { message = "Phone number must start with '+' and contain at least 8 digits." });
        }

        var account = new Account(_client);
            
        try
        {
            // Create user with the specified Name, Email, Password, and Phone number
            var result = await account.Create(
                userId: "unique()",
                email: request.Email,
                password: request.Password,
                name: request.Name
            );

            // After creating the user, you could add custom attributes for phone if Appwrite supports it
            return Ok(new { message = "User registered successfully", userId = result.id });
        }
        catch (AppwriteException ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(string email, string password)
    {
        var account = new Account(_client);
        
        try
        {
            var session = await account.CreateSession(
                email: email,
                password: password
            );

            return Ok(session);
        }
        catch (Exception ex)
        {
            return Unauthorized(new { message = ex.Message });
        }
    }
}
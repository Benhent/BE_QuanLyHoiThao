using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;
using System.Data.SqlClient;
using Newtonsoft.Json.Linq;

namespace BE_QuanLyHoiThao.Controllers;

[ApiController]
[Route("[controller]")]
public class UserController : ControllerBase
{
    private readonly IConfiguration _configuration;
    public UserController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [AllowAnonymous]
    [HttpPost(Name = "LOGIN")]
    [Route("login")]
    public async Task<IActionResult> UserCheckAuthentication()
    {
        try
        {
            if (Request.ContentLength == null || Request.ContentLength == 0)
            {
                return BadRequest(new { message = "Please input Username and Password!" });
            }

            string connectionString = _configuration.GetConnectionString("DefaultConnection");
            using SqlConnection connection = new(connectionString);
            if (connection.State == ConnectionState.Closed)
            {
                await connection.OpenAsync();
            }

            using SqlCommand command = new();
            command.Connection = connection;
            command.CommandType = CommandType.StoredProcedure;
            command.CommandText = "spUserLogin";

            using (var reader = new StreamReader(Request.Body))
            {
                var requestBody = await reader.ReadToEndAsync();

                // Parse the JSON content to a JObject
                var jsonObject = JObject.Parse(requestBody);
                if (jsonObject["UserName"] == null)
                    return BadRequest(new { message = "Please input Username!" });

                command.Parameters.AddWithValue("@UserName", jsonObject["UserName"]?.Value<string>());
                command.Parameters.AddWithValue("@PassWord", jsonObject["PassWord"]?.Value<string>());
            }

            SqlDataAdapter da = new(command);
            DataTable dt = new();
            da.Fill(dt);

            var jwt = new JwtToken();

            var tokenString = jwt.GenerateJwtToken(
                username: dt.Rows[0]["UserName"].ToString()
            );

            return Ok(new { token = tokenString });
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message.ToString() });
        }
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> RegisterUser()
    {
        try
        {
            if (Request.ContentLength == null || Request.ContentLength == 0)
            {
                return BadRequest(new { message = "Please provide user registration details." });
            }

            string connectionString = _configuration.GetConnectionString("DefaultConnection");

            using SqlConnection connection = new(connectionString);
            if (connection.State == ConnectionState.Closed)
            {
                await connection.OpenAsync();
            }

            using SqlCommand command = new();
            command.Connection = connection;
            command.CommandType = CommandType.StoredProcedure;
            command.CommandText = "spRegisterUser";

            using (var reader = new StreamReader(Request.Body))
            {
                var requestBody = await reader.ReadToEndAsync();
                var jsonObject = JObject.Parse(requestBody);

                // Validate input fields
                if (jsonObject["UserName"] == null || jsonObject["PassWord"] == null || jsonObject["FullName"] == null)
                    return BadRequest(new { message = "Please provide Username, Password, and FullName." });

                command.Parameters.AddWithValue("@UserName", jsonObject["UserName"]?.Value<string>());
                command.Parameters.AddWithValue("@FullName", jsonObject["FullName"]?.Value<string>());
                command.Parameters.AddWithValue("@UserStatus", jsonObject["UserStatus"]?.Value<bool>() ?? true); // Default to active
                command.Parameters.AddWithValue("@UserPass", jsonObject["PassWord"]?.Value<string>()); // Pass plaintext password
                command.Parameters.AddWithValue("@PersonalEmail", jsonObject["PersonalEmail"]?.Value<string>());
            }

            await command.ExecuteNonQueryAsync();
            return Ok(new { message = "User registered successfully." });
            }
        catch (SqlException ex) when (ex.Number == 50001)
        {
            return BadRequest(new { message = "Username already exists." });
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }
}

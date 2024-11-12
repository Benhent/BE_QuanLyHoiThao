using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Data;
using System.Data.SqlClient;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Claims;

namespace BE_QuanLyHoiThao.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthorController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly JwtToken _jwt;

    public AuthorController(IConfiguration configuration)
    {
        _configuration = configuration;
        _jwt = new JwtToken();
    }

    [HttpGet]
    public async Task<ActionResult> GetAuthors()
    {
        try
        {
            string? authHeader = Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                return Unauthorized(new { message = "Missing or invalid Authorization header" });
            }

            string token = authHeader["Bearer ".Length..].Trim();

            if (_jwt.ValidateToken(token, out ClaimsPrincipal? claims))
            {
                string connectionString = _configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
                await using SqlConnection connection = new(connectionString);
                if (connection.State == ConnectionState.Closed)
                {
                    await connection.OpenAsync();
                }

                using SqlCommand command = new();
                command.Connection = connection;
                command.CommandType = CommandType.StoredProcedure;
                command.CommandText = "spAuthor_GetAll";

                SqlDataAdapter da = new(command);
                DataTable dt = new();
                da.Fill(dt);

                return new ContentResult
                {
                    Content = JsonConvert.SerializeObject(dt),
                    ContentType = "application/json",
                    StatusCode = 200
                };
            }
            else
            {
                return Unauthorized(new { message = "Token is invalid" });
            }
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpGet("{id}")]
    public async Task<ActionResult> GetAuthorById(int id)
    {
        try
        {
            string? authHeader = Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                return Unauthorized(new { message = "Missing or invalid Authorization header" });
            }

            string token = authHeader["Bearer ".Length..].Trim();

            if (_jwt.ValidateToken(token, out ClaimsPrincipal? claims))
            {
                string connectionString = _configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
                await using SqlConnection connection = new(connectionString);
                if (connection.State == ConnectionState.Closed)
                {
                    await connection.OpenAsync();
                }

                using SqlCommand command = new();
                command.Connection = connection;
                command.CommandType = CommandType.StoredProcedure;
                command.CommandText = "spAuthor_GetById";
                command.Parameters.AddWithValue("@AuthorID", id);

                SqlDataAdapter da = new(command);
                DataTable dt = new();
                da.Fill(dt);

                if (dt.Rows.Count == 0)
                {
                    return NotFound(new { message = "Author not found" });
                }

                return new ContentResult
                {
                    Content = JsonConvert.SerializeObject(dt.Rows[0]),
                    ContentType = "application/json",
                    StatusCode = 200
                };
            }
            else
            {
                return Unauthorized(new { message = "Token is invalid" });
            }
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }

    [HttpPost("add")]
    public async Task<ActionResult> AddAuthor()
    {
        try
        {
            string? authHeader = Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                return Unauthorized(new { message = "Missing or invalid Authorization header" });
            }

            string token = authHeader["Bearer ".Length..].Trim();

            if (_jwt.ValidateToken(token, out ClaimsPrincipal? claims))
            {
                var userName = claims?.FindFirst(c => c.Type == "UserName")?.Value;

                string connectionString = _configuration.GetConnectionString("DefaultConnection") ?? 
                    throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
                    
                await using SqlConnection connection = new(connectionString);
                if (connection.State == ConnectionState.Closed)
                {
                    await connection.OpenAsync();
                }

                using SqlCommand command = new();
                command.Connection = connection;
                command.CommandType = CommandType.StoredProcedure;
                command.CommandText = "spAuthor_Add";

                using (var reader = new StreamReader(Request.Body))
                {
                    var requestBody = await reader.ReadToEndAsync();
                    var jsonObject = JObject.Parse(requestBody);

                    command.Parameters.AddWithValue("@FirstName", jsonObject["FirstName"]?.ToString() ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@LastName", jsonObject["LastName"]?.ToString() ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@Email", jsonObject["Email"]?.ToString() ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@Address", jsonObject["Address"]?.ToString() ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@InstitutionID", jsonObject["InstitutionID"]?.ToObject<int?>() ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@bio", jsonObject["bio"]?.ToString() ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@dateOfbirth", jsonObject["dateOfBirth"]?.ToObject<DateTime?>() ?? (object)DBNull.Value);
                    command.Parameters.AddWithValue("@CreatedBy", userName ?? (object)DBNull.Value);
                }

                SqlDataAdapter da = new(command);
                DataTable dt = new();
                da.Fill(dt);

                if (dt.Rows.Count > 0)
                {
                    var errMsg = dt.Rows[0]["errMsg"].ToString();
                    var authorId = dt.Rows[0]["author_id"] != DBNull.Value ? Convert.ToInt32(dt.Rows[0]["author_id"]) : (int?)null;

                    if (errMsg == "Author created successfully")
                    {
                        return Ok(new { message = errMsg, authorId = authorId });
                    }
                    else
                    {
                        return BadRequest(new { message = errMsg });
                    }
                }
                else
                {
                    return StatusCode(500, new { message = "An unexpected error occurred" });
                }
            }
            else
            {
                return Unauthorized(new { message = "Token is invalid" });
            }
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { message = "An error occurred while processing your request", error = ex.Message });
        }
    }


    [HttpPut("{id}")]
        public async Task<ActionResult> UpdateAuthor(int id)
        {
            try
            {
                string? authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized(new { message = "Missing or invalid Authorization header" });
                }

                string token = authHeader["Bearer ".Length..].Trim();

                if (_jwt.ValidateToken(token, out ClaimsPrincipal? claims))
                {
                    var userName = claims?.FindFirst(c => c.Type == "UserName")?.Value;

                    string connectionString = _configuration.GetConnectionString("DefaultConnection") ?? 
                        throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
                    
                    await using SqlConnection connection = new(connectionString);
                    if (connection.State == ConnectionState.Closed)
                    {
                        await connection.OpenAsync();
                    }

                    using SqlCommand command = new();
                    command.Connection = connection;
                    command.CommandType = CommandType.StoredProcedure;
                    command.CommandText = "spAuthor_Update";

                    using (var reader = new StreamReader(Request.Body))
                    {
                        var requestBody = await reader.ReadToEndAsync();
                        var jsonObject = JObject.Parse(requestBody);

                        command.Parameters.AddWithValue("@AuthorID", id);
                        command.Parameters.AddWithValue("@FirstName", jsonObject["FirstName"]?.ToString() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@LastName", jsonObject["LastName"]?.ToString() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Email", jsonObject["Email"]?.ToString() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Address", jsonObject["Address"]?.ToString() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@InstitutionID", jsonObject["InstitutionID"]?.ToObject<int?>() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@bio", jsonObject["bio"]?.ToString() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@dateOfbirth", jsonObject["dateOfBirth"]?.ToObject<DateTime?>() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@UpdatedBy", userName ?? (object)DBNull.Value);
                    }

                    SqlDataAdapter da = new(command);
                    DataTable dt = new();
                    da.Fill(dt);

                    if (dt.Rows.Count > 0)
                    {
                        var errMsg = dt.Rows[0]["errMsg"].ToString();

                        if (errMsg == "Author updated successfully")
                        {
                            return Ok(new { message = errMsg });
                        }
                        else
                        {
                            return BadRequest(new { message = errMsg });
                        }
                    }
                    else
                    {
                        return StatusCode(500, new { message = "An unexpected error occurred" });
                    }
                }
                else
                {
                    return Unauthorized(new { message = "Token is invalid" });
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while processing your request", error = ex.Message });
            }
        }

    [HttpDelete("{id}")]
    public async Task<ActionResult> DeleteAuthor(int id)
    {
        try
        {
            string? authHeader = Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                return Unauthorized(new { message = "Missing or invalid Authorization header" });
            }

            string token = authHeader["Bearer ".Length..].Trim();

            if (_jwt.ValidateToken(token, out ClaimsPrincipal? claims))
            {
                string connectionString = _configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
                await using SqlConnection connection = new(connectionString);
                if (connection.State == ConnectionState.Closed)
                {
                    await connection.OpenAsync();
                }

                using SqlCommand command = new();
                command.Connection = connection;
                command.CommandType = CommandType.StoredProcedure;
                command.CommandText = "spAuthor_Delete";
                command.Parameters.AddWithValue("@AuthorID", id);

                SqlDataAdapter da = new(command);
                DataTable dt = new();
                da.Fill(dt);

                return new ContentResult
                {
                    Content = JsonConvert.SerializeObject(new { message = dt.Rows[0]["errMsg"] }),
                    ContentType = "application/json",
                    StatusCode = 200
                };
            }
            else
            {
                return Unauthorized(new { message = "Token is invalid" });
            }
        }
        catch (Exception ex)
        {
            return BadRequest(new { message = ex.Message });
        }
    }
}
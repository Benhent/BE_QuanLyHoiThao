using Microsoft.AspNetCore.Mvc;
using System.Data;
using System.Data.SqlClient;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Claims;

namespace BE_QuanLyHoiThao.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AwardController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly JwtToken _jwt;

        public AwardController(IConfiguration configuration)
        {
            _configuration = configuration;
            _jwt = new JwtToken();
        }

        [HttpGet]
        public async Task<ActionResult> GetAwards()
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
                    command.CommandText = "spAward_GetAll";

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
                return StatusCode(500, new { message = "An error occurred while processing your request", error = ex.Message });
            }
        }

        [HttpGet("{id}")]
        public async Task<ActionResult> GetAwardById(int id)
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
                    command.CommandText = "spAward_GetById";
                    command.Parameters.AddWithValue("@AwardID", id);

                    SqlDataAdapter da = new(command);
                    DataTable dt = new();
                    da.Fill(dt);

                    if (dt.Rows.Count == 0)
                    {
                        return NotFound(new { message = "Award not found" });
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
                return StatusCode(500, new { message = "An error occurred while processing your request", error = ex.Message });
            }
        }

        [HttpPost("add")]
        public async Task<ActionResult> AddAward()
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
                    command.CommandText = "spAward_Add";

                    using (var reader = new StreamReader(Request.Body))
                    {
                        var requestBody = await reader.ReadToEndAsync();
                        var jsonObject = JObject.Parse(requestBody);

                        command.Parameters.AddWithValue("@Name", jsonObject["name"]?.ToString() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Description", jsonObject["description"]?.ToString() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@DateReceived", jsonObject["date_received"]?.ToObject<DateTime>() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@AuthorID", jsonObject["author_id"]?.ToObject<int>() ?? (object)DBNull.Value);
                    }

                    SqlDataAdapter da = new(command);
                    DataTable dt = new();
                    da.Fill(dt);

                    if (dt.Rows.Count > 0)
                    {
                        var errMsg = dt.Rows[0]["errMsg"].ToString();
                        var awardId = dt.Rows[0]["award_id"] != DBNull.Value ? 
                            Convert.ToInt32(dt.Rows[0]["award_id"]) : (int?)null;

                        if (errMsg == "Award created successfully")
                        {
                            return Ok(new { message = errMsg, awardId = awardId });
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
        public async Task<ActionResult> UpdateAward(int id)
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
                    command.CommandText = "spAward_Update";

                    using (var reader = new StreamReader(Request.Body))
                    {
                        var requestBody = await reader.ReadToEndAsync();
                        var jsonObject = JObject.Parse(requestBody);

                        command.Parameters.AddWithValue("@AwardID", id);
                        command.Parameters.AddWithValue("@Name", jsonObject["name"]?.ToString() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Description", jsonObject["description"]?.ToString() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@DateReceived", jsonObject["date_received"]?.ToObject<DateTime>() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@AuthorID", jsonObject["author_id"]?.ToObject<int>() ?? (object)DBNull.Value);
                    }

                    SqlDataAdapter da = new(command);
                    DataTable dt = new();
                    da.Fill(dt);

                    if (dt.Rows.Count > 0)
                    {
                        var errMsg = dt.Rows[0]["errMsg"].ToString();

                        if (errMsg == "Award updated successfully")
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
        public async Task<ActionResult> DeleteAward(int id)
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
                    command.CommandText = "spAward_Delete";
                    command.Parameters.AddWithValue("@AwardID", id);

                    SqlDataAdapter da = new(command);
                    DataTable dt = new();
                    da.Fill(dt);

                    if (dt.Rows.Count > 0)
                    {
                        var errMsg = dt.Rows[0]["errMsg"].ToString();

                        if (errMsg == "Award deleted successfully")
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
    }
}
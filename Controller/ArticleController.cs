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
    public class ArticleController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly JwtToken _jwt;

        public ArticleController(IConfiguration configuration)
        {
            _configuration = configuration;
            _jwt = new JwtToken();
        }

        [HttpGet]
        public async Task<ActionResult> GetArticles()
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
                    command.CommandText = "spArticle_GetAll";

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
        public async Task<ActionResult> GetArticleById(int id)
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
                    command.CommandText = "spArticle_GetById";
                    command.Parameters.AddWithValue("@ArticleID", id);

                    SqlDataAdapter da = new(command);
                    DataTable dt = new();
                    da.Fill(dt);

                    if (dt.Rows.Count == 0)
                    {
                        return NotFound(new { message = "Article not found" });
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
        public async Task<ActionResult> AddArticle()
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
                    command.CommandText = "spArticle_Add";

                    using (var reader = new StreamReader(Request.Body))
                    {
                        var requestBody = await reader.ReadToEndAsync();
                        var jsonObject = JObject.Parse(requestBody);

                        command.Parameters.AddWithValue("@Title", jsonObject["title"]?.ToString() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Content", jsonObject["content"]?.ToString() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@PublicationDate", jsonObject["publicationDate"]?.ToObject<DateTime>() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@CategoryID", jsonObject["categoryId"]?.ToObject<int>() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@AuthorIDs", jsonObject["authorIds"]?.ToString() ?? (object)DBNull.Value);
                    }

                    SqlDataAdapter da = new(command);
                    DataTable dt = new();
                    da.Fill(dt);

                    if (dt.Rows.Count > 0)
                    {
                        var errMsg = dt.Rows[0]["errMsg"].ToString();
                        var articleId = dt.Rows[0]["article_id"] != DBNull.Value ? 
                            Convert.ToInt32(dt.Rows[0]["article_id"]) : (int?)null;

                        if (errMsg == "Article created successfully")
                        {
                            return Ok(new { message = errMsg, articleId = articleId });
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
        public async Task<ActionResult> UpdateArticle(int id)
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
                    command.CommandText = "spArticle_Update";

                    using (var reader = new StreamReader(Request.Body))
                    {
                        var requestBody = await reader.ReadToEndAsync();
                        var jsonObject = JObject.Parse(requestBody);

                        command.Parameters.AddWithValue("@ArticleID", id);
                        command.Parameters.AddWithValue("@Title", jsonObject["title"]?.ToString() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Content", jsonObject["content"]?.ToString() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@PublicationDate", jsonObject["publicationDate"]?.ToObject<DateTime>() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@CategoryID", jsonObject["categoryId"]?.ToObject<int>() ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@AuthorIDs", jsonObject["authorIds"]?.ToString() ?? (object)DBNull.Value);
                    }

                    SqlDataAdapter da = new(command);
                    DataTable dt = new();
                    da.Fill(dt);

                    if (dt.Rows.Count > 0)
                    {
                        var errMsg = dt.Rows[0]["errMsg"].ToString();

                        if (errMsg == "Article updated successfully")
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
        public async Task<ActionResult> DeleteArticle(int id)
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
                    command.CommandText = "spArticle_Delete";
                    command.Parameters.AddWithValue("@ArticleID", id);

                    SqlDataAdapter da = new(command);
                    DataTable dt = new();
                    da.Fill(dt);

                    if (dt.Rows.Count > 0)
                    {
                        var errMsg = dt.Rows[0]["errMsg"].ToString();

                        if (errMsg == "Article deleted successfully")
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
// using Microsoft.AspNetCore.Authorization;
// using Microsoft.AspNetCore.Mvc;
// using System.Data;
// using System.Data.SqlClient;
// using Newtonsoft.Json;
// using Newtonsoft.Json.Linq;
// using System.Security.Claims;

// namespace BE_QuanLyHoiThao.Controllers;

// [ApiController]
// [Route("[controller]")]
// public class AuthorController : ControllerBase
// {
//     private readonly IConfiguration _configuration;
//     private readonly JwtToken _jwt;

//     public AuthorController(IConfiguration configuration)
//     {
//         _configuration = configuration;
//         _jwt = new JwtToken();
//     }

//     [HttpPost]
//     public async Task<ActionResult> PostAuthor()
//     {
//         try
//         {
//             string authHeader = Request.Headers["Authorization"];
//             if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
//             {
//                 return Unauthorized(new { message = "Missing or invalid Authorization header" });
//             }

//             string token = authHeader["Bearer ".Length..].Trim();

//             if (_jwt.ValidateToken(token, out ClaimsPrincipal? claims))
//             {
//                 var userName = claims?.FindFirst(c => c.Type == "UserName")?.Value;

//                 string connectionString = _configuration.GetConnectionString("DefaultConnection");
//                 using SqlConnection connection = new(connectionString);
//                 if (connection.State == ConnectionState.Closed)
//                 {
//                     await connection.OpenAsync();
//                 }

//                 using SqlCommand command = new();
//                 command.Connection = connection;
//                 command.CommandType = CommandType.StoredProcedure;
//                 command.CommandText = "spAuthor_Save";

//                 using (var reader = new StreamReader(Request.Body))
//                 {
//                     var requestBody = await reader.ReadToEndAsync();
//                     var jsonObject = JObject.Parse(requestBody);

//                     command.Parameters.AddWithValue("@AuthorID", jsonObject["AuthorID"]?.Value<int>() ?? DBNull.Value);
//                     command.Parameters.AddWithValue("@Name", jsonObject["Name"]?.Value<string>());
//                     command.Parameters.AddWithValue("@Bio", jsonObject["Bio"]?.Value<string>());
//                     command.Parameters.AddWithValue("@DateOfBirth", jsonObject["DateOfBirth"]?.Value<DateTime?>() ?? DBNull.Value);
//                     command.Parameters.AddWithValue("@CreatedBy", userName);
//                 }

//                 SqlDataAdapter da = new(command);
//                 DataTable dt = new();
//                 da.Fill(dt);

//                 return new ContentResult
//                 {
//                     Content = JsonConvert.SerializeObject(new { message = dt.Rows[0]["errMsg"] }),
//                     ContentType = "application/json",
//                     StatusCode = 200
//                 };
//             }
//             else
//             {
//                 return Unauthorized(new { message = "Token is invalid" });
//             }
//         }
//         catch (Exception ex)
//         {
//             return BadRequest(new { message = ex.Message });
//         }
//     }
// }

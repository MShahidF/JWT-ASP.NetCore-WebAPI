using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;

using JWT_ASP.NetCore_WebAPI.Models;
using JWT_ASP.NetCore_WebAPI.Repositories;

namespace JWT_ASP.NetCore_WebAPI.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class LoginController : ControllerBase
  {
    private readonly IConfiguration _configuration;

    public LoginController(IConfiguration configuration)
    {
      _configuration = configuration;
    }

    [AllowAnonymous]
    [HttpPost]
    public IActionResult Login([FromBody] UserLogin userLogin)
    {
      var user = AuthenticateUser(userLogin);

      if (user is null)
      {
        return NotFound("User not found");
      }

      var token = GenerateToken(user);

      return Ok(token);
    }

    private User AuthenticateUser(UserLogin userLogin)
    {
      var currentUser = UserRepository.Users.FirstOrDefault(option =>
        option.UserName.ToLower() == userLogin.UserName.ToLower() && option.Password == userLogin.Password);

      if (currentUser is null)
      {
        return null;
      }

      return currentUser;
    }

    private string GenerateToken(User user)
    {
      var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
      var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

      var claims = new[]
      {
        new Claim(ClaimTypes.NameIdentifier, user.UserName),
        new Claim(ClaimTypes.Email, user.EmailAddress),
        new Claim(ClaimTypes.Role, user.Role)
      };

      var token = new JwtSecurityToken(_configuration["Jwt:Issuer"],
        _configuration["Jwt:Audience"],
        claims,
        expires: DateTime.Now.AddMinutes(15),
        signingCredentials: credentials);

      return new JwtSecurityTokenHandler().WriteToken(token);
    }
  }
}

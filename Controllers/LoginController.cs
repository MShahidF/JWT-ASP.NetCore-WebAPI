using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

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

    [HttpPost("login")]
    public IActionResult Login([FromBody] UserLogin userLogin)
    {
      var user = AuthenticateUser(userLogin);

      if (user is null)
      {
        return NotFound("User not found");
      }

      var token = GenerateToken(user);

      if (token == null)
      {
        return Unauthorized("Invalid Attempt!");
      }

      var indexOf = UserRepository.Users.IndexOf(user);

      UserRepository.Users[indexOf].RefreshToken = token.RefreshToken;

      return Ok(token);
    }

    [HttpPost("refresh")]
    public IActionResult Refresh(string expiredToken)
    {
      var principle = GetPrincipalFromExpiredToken(expiredToken);
      var userName = principle.Claims.FirstOrDefault(option => option.Type == ClaimTypes.NameIdentifier)?.Value;
      var refreshToken = principle.Claims.FirstOrDefault(x => x.Type.Equals("RefreshToken", StringComparison.OrdinalIgnoreCase))?.Value;
      var user = UserRepository.Users.FirstOrDefault(option => option.UserName.ToLower() == userName.ToLower());

      if (user.RefreshToken != refreshToken)
      {
        return Unauthorized();
      }

      var token = GenerateToken(user);

      if (token == null)
      {
        return Unauthorized();
      }

      var indexOf = UserRepository.Users.IndexOf(user);

      UserRepository.Users[indexOf].RefreshToken = token.RefreshToken;

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

    private Token? GenerateToken(User user)
    {
      try
      {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var tokenHandler = new JwtSecurityTokenHandler();
        var refreshToken = GenerateRefreshToken();

        var claims = new[]
        {
          new Claim(ClaimTypes.NameIdentifier, user.UserName),
          new Claim(ClaimTypes.Email, user.EmailAddress),
          new Claim(ClaimTypes.Role, user.Role),
          new Claim("RefreshToken", refreshToken, ClaimValueTypes.String)
        };

        var accessToken = tokenHandler.CreateJwtSecurityToken(
          _configuration["Jwt:Issuer"],
          _configuration["Jwt:Audience"],
          subject: new ClaimsIdentity(claims),
          expires: DateTime.Now.AddMinutes(1),
          signingCredentials: credentials);

        return new Token
        {
          AccessToken = tokenHandler.WriteToken(accessToken),
          RefreshToken = refreshToken
        };
      }
      catch (Exception ex)
      {
        return null;
      }
    }

    private string GenerateRefreshToken()
    {
      var randomNumber = new byte[32];

      using (var randomNumberGenerator = RandomNumberGenerator.Create())
      {
        randomNumberGenerator.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
      }
    }

    private ClaimsPrincipal GetPrincipalFromExpiredToken(string expiredToken)
    {
      var key = Encoding.UTF8.GetBytes(_configuration["JWT:Key"]);
      var tokenHandler = new JwtSecurityTokenHandler();
      SecurityToken validatedToken;

      var tokenValidationParameters = new TokenValidationParameters
      {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = false,
        ValidateIssuerSigningKey = true,
        ValidIssuer = _configuration["Jwt:Issuer"],
        ValidAudience = _configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ClockSkew = TimeSpan.Zero
      };

      var principal = tokenHandler.ValidateToken(expiredToken, tokenValidationParameters, out validatedToken);

      JwtSecurityToken? jwtToken = validatedToken as JwtSecurityToken;

      if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256))
      {
        throw new SecurityTokenException("Invalid token");
      }

      return principal;
    }
  }
}

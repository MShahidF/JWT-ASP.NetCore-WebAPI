namespace JWT_ASP.NetCore_WebAPI.Models
{
  public class Token
  {
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
  }
}
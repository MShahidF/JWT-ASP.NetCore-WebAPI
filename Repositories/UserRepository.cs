using JWT_ASP.NetCore_WebAPI.Models;

namespace JWT_ASP.NetCore_WebAPI.Repositories
{
  public class UserRepository
  {
    public static List<User> Users = new List<User>()
    {
      new User() { UserName = "admin", Password= "admin", Role="Administrator", EmailAddress = "admin@test.com" },
      new User() { UserName = "test", Password= "test", Role="Standard", EmailAddress = "test@test.com" }
    };
  }
}
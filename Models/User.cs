using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing.Constraints;

namespace CookieBasedAuthentication.Models;

// You build your own Entity but you need to inheritance on IdentityUser
public class User : IdentityUser
{   
    public required string FName {get; set;}
    public required string LName {get; set;}
    
}
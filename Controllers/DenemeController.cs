using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;

namespace CookieBasedAuthentication.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = "UserPolicy")]
public class DenemeController : Controller
{
    [HttpGet("get")]
    public IActionResult Get()
    {
        return Ok("Hi!"); 
    }

    [HttpGet("cookie-auth-test")]
    public IActionResult CookieAuthTest()
    {
        var token = Request.Cookies["AuthToken"];
        if (string.IsNullOrEmpty(token))
        {
            return Unauthorized("Çerez bulunamadı.");
        }

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadToken(token) as JwtSecurityToken;

        if (jwtToken == null)
        {
            return Unauthorized("Geçersiz çerez.");
        }

        var userNameClaim = jwtToken.Claims.FirstOrDefault(claim => claim.Type == ClaimTypes.Name || claim.Type == "unique_name");
        return Ok($"Çerez doğrulandı. Kullanıcı: {userNameClaim?.Value}");
    }
}
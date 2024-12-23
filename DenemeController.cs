using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Authentication.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "User")] 
public class DenemeController : Controller
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok("Hi!"); 
    }
}

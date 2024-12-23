using AutoMapper;
using CookieBasedAuthentication.Models;
using CookieBasedAuthentication.Models.Dtos;
using CookieBasedAuthentication.Services.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;


namespace CookieBasedAuthentication.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : Controller
    {
        private readonly IServiceManager _serviceManager;
        private readonly IMapper _mapper;

        public AccountController(IServiceManager serviceManager, IMapper mapper)
        {
            _serviceManager = serviceManager;
            _mapper = mapper;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return Json(new { success = false, errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList() });
                }

                User user = _mapper.Map<User>(registerDto);
                var (succeeded, errors) = await _serviceManager.AuthService.Register(user, registerDto.Password);

                if (succeeded)
                {
                    await _serviceManager.AuthService.GenerateCookieAuthentication(registerDto.UserName);
                    return Json(new { success = true });
                }
                else
                {
                    foreach (var error in errors!)
                    {
                        string customErrorMessage = error switch
                        {
                            "PasswordTooShort" => "Password must be at least 6 characters long.",
                            "PasswordRequiresNonAlphanumeric" => "Password must contain at least one non-alphanumeric character.",
                            "DuplicateUserName" => "UsernameAlreadyTaken",
                            "DuplicateEmail" => "EmailAlreadyTaken",
                            _ => error
                        };

                        ModelState.AddModelError(string.Empty, customErrorMessage);
                    }
                }
            }
            catch (Exception e)
            {
                ModelState.AddModelError(string.Empty, $"An error occurred: {e.Message}");
            }

            return Json(new { success = false, errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList() });
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return Json(new { success = false, errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList() });
                }

                var (succeeded, errors) = await _serviceManager.AuthService.Login(loginDto);

                if (!succeeded)
                {
                    foreach (var error in errors)
                    {
                        ModelState.AddModelError(string.Empty, error);
                    }
                    return Json(new { success = false, errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList() });
                }

                return Json(new { success = true, });
            }
            catch (Exception e)
            {
                ModelState.AddModelError(string.Empty, $"An error occurred: {e.Message}");
                return Json(new { success = false, errors = ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage).ToList() });
            }
        }

        [HttpPost("logout")]
        [AllowAnonymous]
        public async Task Logout()
        {
            await _serviceManager.AuthService.Logout();
        }
    }
}
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using CookieBasedAuthentication.Models;
using CookieBasedAuthentication.Models.Dtos;
using CookieBasedAuthentication.Services.Contracts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace CookieBasedAuthentication.Services.Concrete;
public class AuthService : IAuthService  // Implements IAuthService interface
{
    private readonly UserManager<User> _userManager;  // Manages user creation, deletion, and password management
    private readonly RoleManager<IdentityRole> _roleManager;  // Manages user roles
    private readonly IHttpContextAccessor _httpContext;  // Provides access to the current HTTP context
    private readonly IConfiguration _config;  // Access to appsettings.json configurations (JWT settings)

    // Constructor - Dependency injection of required services
    public AuthService(UserManager<User> userManager, RoleManager<IdentityRole> roleManager, IHttpContextAccessor httpContext, IConfiguration config)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _httpContext = httpContext;
        _config = config;
    }

    // Adds a claim to a specific user
    public async Task<bool> AddUserClaim(string user, Claim claim)
    {
        var userEntity = await _userManager.FindByNameAsync(user);  // Find user by username
        if (userEntity == null)
            return false;  // Return false if user doesn't exist
        var result = await _userManager.AddClaimAsync(userEntity, claim);  // Add claim to user
        return result.Succeeded;  // Return if the operation succeeded
    }

    // Generates JWT token for cookie authentication
    public async Task<string> GenerateCookieAuthentication(string userName)
    {
        var claims = await GetUserClaims(userName);  // Get user claims (roles, name, etc.)
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT:SigninKey"]!));  // Signin key from appsettings.json
        var signingCred = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha512Signature);  // HMAC SHA-512 signature for token signing

        var securityToken = new JwtSecurityToken(
            issuer: _config["JWT:Issuer"],  // JWT Issuer
            audience: _config["JWT:Audience"],  // JWT Audience
            expires: DateTime.Now.AddMinutes(60),  // Token expiration time
            claims: claims,  // User claims to include in the token
            signingCredentials: signingCred  // Signing credentials for security
        );
        string token = new JwtSecurityTokenHandler().WriteToken(securityToken);  // Create and return token as a string
        _httpContext.HttpContext?.Response.Cookies.Append("AuthToken", token, new CookieOptions
        {
            HttpOnly = true,  // Cookie accessible only by the server (not JavaScript)
            Secure = false,  // Set to false for development (should be true in production for HTTPS)
            SameSite = SameSiteMode.Strict,  // Prevent cookie from being sent with cross-site requests
            Expires = DateTimeOffset.UtcNow.AddMinutes(60)  // Set cookie expiration time
        });
        return token;
    }

    // Retrieves all user claims including roles and custom claims
    public async Task<List<Claim>> GetUserClaims(string userName)
    {
        var user = await _userManager.FindByNameAsync(userName);  // Find user by username
        var claims = new List<Claim>()
        {
            new Claim(ClaimTypes.Name, userName),  // Add username as a claim
        };
        claims.AddRange(await _userManager.GetClaimsAsync(user!));  // Add existing user claims
        var roles = await _userManager.GetRolesAsync(user!);  // Get user roles

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));  // Add role as a claim
            var identityRole = await _roleManager.FindByNameAsync(role);  // Find the role in IdentityRole
            claims.AddRange(await _roleManager.GetClaimsAsync(identityRole!));  // Add claims associated with the role
        }
        return claims;
    }

    // Handles user login and generates cookie with JWT token
    public async Task<(bool Succeeded, string[] Errors)> Login(LoginDto loginDto)
    {
        var user = await _userManager.FindByNameAsync(loginDto.UserName);  // Find user by username
        if (user == null)
        {
            return (false, new[] { "User does not exist" });  // Return false if user doesn't exist
        }

        var isPasswordValid = await _userManager.CheckPasswordAsync(user, loginDto.Password);  // Check if password is valid
        if (!isPasswordValid)
        {
            return (false, new[] { "Invalid Username" });  // Return false if password is incorrect
        }

        await GenerateCookieAuthentication(loginDto.UserName);  // Generate JWT token But we dont use now

        return (true, Array.Empty<string>());  // Return true if login is successful
    }

    // Logs the user out and clears the authentication cookie
    public async Task Logout()
    {
        var httpContext = _httpContext.HttpContext;
        if (httpContext != null)
        {
            await httpContext.SignOutAsync();
            httpContext.Response.Cookies.Delete("X-Access-Token");
        }
    }

    // Registers a new user with default role "User"
    public async Task<(bool Succeeded, string[]? Errors)> Register(User profile, string password)
    {
        var result = await _userManager.CreateAsync(profile, password);
        if (!result.Succeeded)
        {
            return (false, result.Errors.Select(e => e.Description).ToArray());
        }
        // Usera döndür
        var role = "User";
        var roleResult = await _userManager.AddToRoleAsync(profile, role);

        if (!roleResult.Succeeded)
        {
            return (false, roleResult.Errors.Select(e => e.Description).ToArray());
        }

        return (true, null);
    }
}

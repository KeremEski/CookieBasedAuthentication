using System.Security.Claims;
using CookieBasedAuthentication.Models;
using CookieBasedAuthentication.Models.Dtos;

namespace CookieBasedAuthentication.Services.Contracts;

public interface IAuthService
{
    Task<(bool Succeeded, string[] Errors)> Login(LoginDto loginDto);
    Task Logout();
    Task<(bool Succeeded, string[]? Errors)> Register(User profile, string password);
    Task<bool> AddUserClaim(string user,Claim claim);
    Task<string> GenerateCookieAuthentication(string userName);
    Task<List<Claim>> GetUserClaims(string userName);
}
namespace CookieBasedAuthentication.Models.Dtos;

public record RegisteredUserDto()
{
    public required string Email { get; set; }
    public required string UserName { get; set; }
    public required string Token { get; set; }

}
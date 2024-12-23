namespace CookieBasedAuthentication.Models.Dtos;
public record RegisterDto
{
    public required string Email { get; set; }
    public required string Password { get; set; }
    public required string UserName { get; set; }
    public required string FName { get; set; }
    public required string LName { get; set; }
    
    

}
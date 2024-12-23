using CookieBasedAuthentication.Services.Contracts;

namespace CookieBasedAuthentication.Services.Contracts;

public interface IServiceManager
{
    IAuthService AuthService {get;}
}
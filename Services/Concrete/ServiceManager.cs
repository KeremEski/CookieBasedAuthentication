using CookieBasedAuthentication.Services.Contracts;

namespace CookieBasedAuthentication.Services.Concrete;

public class ServiceManager : IServiceManager
{

    private readonly IAuthService _authService;
    public ServiceManager(IAuthService authService)
    {
        _authService = authService;
    }

    public IAuthService AuthService => _authService;
}
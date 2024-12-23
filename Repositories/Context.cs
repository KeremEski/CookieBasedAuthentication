
using CookieBasedAuthentication.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CookieBasedAuthentication.Repositories;

// Important: You need to use IdentityDbContext<Entity>. It will crate special tables.
public class Context : IdentityDbContext<User>
{
    public Context(DbContextOptions<Context> options) : base(options)
    {

    }

}
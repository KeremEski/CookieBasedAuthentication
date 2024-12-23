using System.Text;
using CookieBasedAuthentication.Models;
using CookieBasedAuthentication.Repositories;
using CookieBasedAuthentication.Services.Concrete;
using CookieBasedAuthentication.Services.Contracts;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);
// Auto Mapper Configurations
builder.Services.AddAutoMapper(typeof(Program));
// Add services to the container.
builder.Services.AddControllersWithViews();

// Database Configurations
builder.Services.AddDbContext<Context>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));  // Connect to PostgreSQL database

// Retrieve JWT settings from appsettings.json
var jwtKey = builder.Configuration["JWT:SigninKey"];
var jwtIssuer = builder.Configuration["JWT:Issuer"];
var jwtAudience = builder.Configuration["JWT:Audience"];

// Identity Configurations - Setup Identity framework for user management
builder.Services.AddIdentity<User, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;  // Password must contain a digit
    options.Password.RequiredLength = 8;   // Minimum password length
    options.Password.RequireNonAlphanumeric = true;  // Require at least one non-alphanumeric character
}).AddEntityFrameworkStores<Context>();  // Use Entity Framework to store Identity data in the database

// Authentication settings - Configure cookie and JWT authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;  // Use JWT for default authentication
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;    // Use JWT for default challenge
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;  // Use cookie for sign-in
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.LoginPath = "/account/login";  // Redirect to login page if authentication fails
    options.LogoutPath = "/account/logout";
    options.AccessDeniedPath = "/access-denied";  // Redirect if access is denied
    options.Cookie.Name = "AuthToken";  // Name of the cookie used for authentication
    options.Cookie.HttpOnly = true;  // Make the cookie accessible only via HTTP (not JavaScript)
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);  // Cookie expiration time
    options.SlidingExpiration = true;  // Renew the cookie if the user is active
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            // First, try to get the token from the cookie
            var token = context.Request.Cookies["AuthToken"];

            // If the cookie contains a token, use it
            if (!string.IsNullOrEmpty(token))
            {
                context.Token = token;
            }
            // If no cookie, check the Authorization header for a Bearer token
            else
            {
                var authorizationHeader = context.Request.Headers["Authorization"].ToString();
                if (!string.IsNullOrEmpty(authorizationHeader) && authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    context.Token = authorizationHeader.Substring("Bearer ".Length).Trim();
                }
            }

            return Task.CompletedTask;
        }
    };

    // Token validation parameters for verifying JWT tokens
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["JWT:Issuer"],  // Issuer from appsettings.json
        ValidAudience = builder.Configuration["JWT:Audience"],  // Audience from appsettings.json
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["JWT:SigninKey"]!))  // JWT signing key from appsettings.json
    };
});

// Authorization policies - Define custom policies for different user roles
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("UserPolicy", policy =>
    {
        policy.RequireAuthenticatedUser();  // Require user to be authenticated
        policy.RequireRole("User");  // Allow access only to users with the "User" role
    });
    options.AddPolicy("AdminPolicy", policy =>
    {
        policy.RequireAuthenticatedUser();  // Require user to be authenticated
        policy.RequireRole("Admin");  // Allow access only to users with the "Admin" role
    });
});

// Optional: Configure Swagger for API documentation and token testing
builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo { Title = "Demo API", Version = "v1" });
    option.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter a valid token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });
    option.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] { }
        }
    });
});

// Register application services (Dependency Injection)
builder.Services.AddScoped<IServiceManager, ServiceManager>();
builder.Services.AddScoped<IAuthService, AuthService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");  // Redirect to error page in production
    app.UseHsts();  // Enable HSTS (HTTP Strict Transport Security)
}

// Enable Swagger and Swagger UI for API documentation
app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();  // Force HTTPS
app.UseRouting();  // Enable routing for the application

// Add authentication and authorization middleware
app.UseAuthentication();  // Authenticate users
app.UseAuthorization();  // Authorize users based on policies

app.MapControllers();  // Map controller endpoints to routes

// Serve static assets (like CSS, JS, images)
app.MapStaticAssets();

// Configure the default route for the application
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();  // Run the application

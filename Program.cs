using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.WebUtilities;
using System.Data.SqlClient;
using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

// Setup in-memory database for simplicity in this single-file example
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseInMemoryDatabase("InMemoryDb"));

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddAuthentication();
builder.Services.AddAuthorization();
builder.Services.AddSingleton<AuthService>();
builder.Services.AddSingleton<TestService>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/login", ([FromServices] AuthService authService, string username, string password) =>
{
    if (authService.LoginUser(username, password))
    {
        return Results.Ok("Login successful.");
    }
    return Results.Unauthorized("Invalid credentials.");
});

app.MapGet("/api/sanitize", ([FromServices] ValidationHelpers, string userInput) =>
{
    var sanitizedInput = ValidationHelpers.SanitizeInput(userInput);
    return Results.Ok($"Sanitized Input: {sanitizedInput}");
});

app.MapGet("/api/manage-users", ([FromServices] TestService testService) =>
{
    return Results.Ok("Only admins can access this.");
});

app.Run();

// Supporting Classes
public class ApplicationDbContext : IdentityDbContext<IdentityUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options) { }
}

public class AuthService
{
    private readonly string _connectionString = "your-connection-string"; // Replace with actual connection string

    public bool LoginUser(string username, string password)
    {
        const string allowedSpecialCharacters = "@#$%&*!";
        if (!ValidationHelpers.IsValidInput(username) || !ValidationHelpers.IsValidInput(password, allowedSpecialCharacters))
        {
            return false;
        }

        // Dummy SQL logic for simplicity
        return username == "admin" && password == "admin";
    }
}

public static class ValidationHelpers
{
    public static bool IsValidInput(string input, string allowedSpecialCharacters = "")
    {
        if (string.IsNullOrEmpty(input)) return false;

        var validCharacters = new HashSet<char>(allowedSpecialCharacters);
        return input.All(c => char.IsLetterOrDigit(c) || validCharacters.Contains(c));
    }

    public static string SanitizeInput(string input)
    {
        return HtmlEncoder.Default.Encode(input);
    }
}

public class TestService
{
    private readonly AuthService _authService;

    public TestService(AuthService authService)
    {
        _authService = authService;
    }

    public bool TestSqlInjection()
    {
        string maliciousInput = "' OR 1=1 --";
        return _authService.LoginUser(maliciousInput, "password");
    }

    public bool TestXSS()
    {
        string maliciousInput = "<script>alert('XSS')</script>";
        return !ValidationHelpers.IsValidInput(maliciousInput);
    }
}

using JeffOps.Authentication.Endpoints;
using JeffOps.Authentication.Federation.Entra;
using JeffOps.Authentication.Infrastructure.DependencyInjection;
using JeffOps.Authentication.Persistence.SqlServer;
using JeffOps.Authentication.UI;
using JeffOps.Security.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Hardening baseline and the key ring that protects token keys at rest (docs/DESIGN.md §16).
builder.Services.AddJeffOpsSecurity(builder.Configuration);
builder.Services.AddJeffOpsDataProtection(builder.Configuration);

// The token server with SQL Server storage and Microsoft Entra ID sign-in. Add more providers with AddOidcProvider("name").
var authentication = builder.Services.AddJeffOpsAuthentication(builder.Configuration)
    .AddSqlServerPersistence(migrateOnStartup: builder.Environment.IsDevelopment());
if (!string.IsNullOrEmpty(builder.Configuration["JeffOps:TokenServer:Federation:Providers:entra:ClientId"]))
{
    authentication.AddEntra();
}

builder.Services.AddJeffOpsAuthenticationUI();

// The sign-in session the authorize endpoint reads; the login UI signs users into it.
builder.Services.AddAuthentication()
    .AddCookie("JeffOps.SignIn", options =>
    {
        options.Cookie.Name = "__Host-jeffops-signin";
        options.LoginPath = "/account/login";
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = false;
    });

var app = builder.Build();

app.UseJeffOpsSecurity();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();
app.MapStaticAssets();
app.MapJeffOpsAuthentication();
app.MapJeffOpsAuthenticationUI();
app.MapGet("/health", () => Results.Ok()).AllowAnonymous();

app.Run();

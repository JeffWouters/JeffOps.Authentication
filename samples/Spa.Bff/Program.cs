using JeffOps.Authentication.Bff;
using JeffOps.Authentication.Bff.Yarp;
using JeffOps.Security.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Outside Development the BFF refuses to start without a shared distributed cache (for example
// AddStackExchangeRedisCache) and a persisted key ring encrypted with a KEK (JeffOps:DataProtection:KekCertificate plus
// .PersistKeysToRedis(...)). In Development, sessions live in memory and keys in the default local key store.
builder.Services.AddJeffOpsSecurity(builder.Configuration);
builder.Services.AddJeffOpsDataProtection(builder.Configuration);
builder.Services.AddJeffOpsBff(builder.Configuration);       // sign-in, sessions, refresh, back-channel logout
var patExchange = !string.IsNullOrEmpty(builder.Configuration["JeffOps:PatExchange:ClientSecret"]);
if (patExchange)
{
    builder.Services.AddJeffOpsPatExchange(builder.Configuration); // personal access tokens at the edge
}

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddBffTransforms();

var app = builder.Build();

app.UseJeffOpsSecurity();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseJeffOpsBff();          // CSRF header check, then session cookie → bearer token
if (patExchange)
{
    app.UseJeffOpsPatExchange();  // Bearer pat_… → short-lived JWT
}

app.MapJeffOpsBff();          // /bff/login, /bff/callback, /bff/logout, /bff/me, /bff/backchannel-logout
app.MapReverseProxy();        // /api/** → the API, with the bearer token and without the cookie

app.Run();

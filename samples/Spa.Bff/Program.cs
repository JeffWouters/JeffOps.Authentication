using JeffOps.Authentication.Bff;
using JeffOps.Authentication.Bff.Yarp;
using JeffOps.Security.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddJeffOpsSecurity(builder.Configuration);
builder.Services.AddJeffOpsBff(builder.Configuration);       // sign-in, sessions, refresh, back-channel logout
builder.Services.AddJeffOpsPatExchange(builder.Configuration); // personal access tokens at the edge
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddBffTransforms();

var app = builder.Build();

app.UseJeffOpsSecurity();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseJeffOpsBff();          // CSRF header check, then session cookie → bearer token
app.UseJeffOpsPatExchange();  // Bearer pat_… → short-lived JWT
app.MapJeffOpsBff();          // /bff/login, /bff/callback, /bff/logout, /bff/me, /bff/backchannel-logout
app.MapReverseProxy();        // /api/** → the API, with the bearer token and without the cookie

app.Run();

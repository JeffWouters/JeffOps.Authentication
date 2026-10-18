using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Enterprise.Endpoints;
using JeffOps.Authentication.Enterprise.Infrastructure;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests.Performance;

/// <summary>
/// Measures how many database commands the hot paths cost, per request, and writes a report (with the SQL) to the file in
/// <c>JEFFOPS_PROBE_REPORT</c>. Runs only with <c>JEFFOPS_PROBE=1</c>, and alone: the counter sees the whole process.
/// </summary>
public sealed class RoundTripProbe
{
    private static readonly Guid Contoso = Guid.NewGuid();
    private const string TokenUrl = "https://localhost/connect/token";

    public static bool Enabled => Environment.GetEnvironmentVariable("JEFFOPS_PROBE") == "1";

    [Fact(SkipUnless = nameof(Enabled), Skip = "Set JEFFOPS_PROBE=1 to run the round-trip probe.")]
    public async Task Measure_round_trips_per_request()
    {
        using var counter = new QueryCounter();
        var report = new StringBuilder();
        report.AppendLine($"# Round trips per request ({(TestDatabase.SqlServer ? "SQL Server" : "SQLite")})").AppendLine();
        report.AppendLine("| Request | Commands | By context |").AppendLine("|---|---:|---|");
        var details = new StringBuilder();

        async Task MeasureAsync(string name, Func<Task> request)
        {
            await request();   // warm-up: caches, compiled queries, first-use initialisation
            var best = int.MaxValue;
            IReadOnlyList<(string Context, string Sql)> commands = [];
            for (var run = 0; run < 3; run++)
            {
                await Task.Delay(50, TestContext.Current.CancellationToken);
                counter.Reset();
                await request();
                var seen = counter.Commands;
                if (seen.Count < best)
                {
                    best = seen.Count;
                    commands = seen;
                }
            }

            var byContext = string.Join(", ", commands.GroupBy(command => command.Context).Select(group => $"{group.Key} {group.Count()}"));
            report.AppendLine($"| {name} | {best} | {byContext} |");
            details.AppendLine($"## {name} ({best})").AppendLine();
            foreach (var (context, sql) in commands)
            {
                details.AppendLine($"- `{context}`: `{string.Join(' ', sql.Split((char[])['\r', '\n'], StringSplitOptions.RemoveEmptyEntries).Select(line => line.Trim()))}`");
            }

            details.AppendLine();
        }

        await using (var host = await TokenServerHost.StartAsync(new()
        {
            ["JeffOps:TokenServer:Clients:3:ClientId"] = "dpop-svc",
            ["JeffOps:TokenServer:Clients:3:ClientSecret"] = "dpop-svc-secret-that-is-at-least-thirty-two-chars",
            ["JeffOps:TokenServer:Clients:3:GrantTypes:0"] = "client_credentials",
            ["JeffOps:TokenServer:Clients:3:Scopes:0"] = "api",
        }))
        {
            var account = await host.CreateAccountAsync("ada@example.com");
            host.Tenants.AddMembership(account.Id);
            var session = await host.SignInAsync(account.Id);
            var refresh = session.RefreshToken!;
            var pat = await CreatePatAsync(host, session.AccessToken!);

            await MeasureAsync("GET discovery", () => host.Client.GetAsync(new Uri(".well-known/openid-configuration", UriKind.Relative), TestContext.Current.CancellationToken));
            await MeasureAsync("GET jwks", () => host.Client.GetAsync(new Uri(".well-known/jwks", UriKind.Relative), TestContext.Current.CancellationToken));
            await MeasureAsync("token: client_credentials", () => host.ClientCredentialsAsync());
            await MeasureAsync("token: client_credentials + DPoP", async () =>
            {
                using var key = new DpopKey();
                using var request = new HttpRequestMessage(HttpMethod.Post, "connect/token")
                {
                    Content = new FormUrlEncodedContent(new Dictionary<string, string>
                    {
                        ["grant_type"] = "client_credentials", ["client_id"] = "dpop-svc", ["client_secret"] = "dpop-svc-secret-that-is-at-least-thirty-two-chars", ["scope"] = "api",
                    }),
                };
                request.Headers.Add("DPoP", key.Proof("POST", TokenUrl));
                (await host.Client.SendAsync(request, TestContext.Current.CancellationToken)).EnsureSuccessStatusCode();
            });
            await MeasureAsync("authorize (signed in) → code", () => host.AuthorizeAsync(account.Id));
            await MeasureAsync("authorize + token: authorization_code", () => host.SignInAsync(account.Id));
            await MeasureAsync("token: refresh_token", async () =>
            {
                var renewed = await host.RefreshAsync(refresh);
                refresh = renewed.RefreshToken ?? throw new InvalidOperationException(renewed.Body.ToString());
            });
            await MeasureAsync("token: PAT exchange", () => host.ExchangePatAsync(pat));
            await MeasureAsync("userinfo", () => host.SendAsync(HttpMethod.Get, "connect/userinfo", session.AccessToken));
            await MeasureAsync("introspect", async () =>
            {
                using var request = new HttpRequestMessage(HttpMethod.Post, "connect/introspect")
                {
                    Content = new FormUrlEncodedContent(new Dictionary<string, string>
                    {
                        ["token"] = session.AccessToken!, ["client_id"] = TokenServerHost.GatewayClient, ["client_secret"] = TokenServerHost.GatewaySecret,
                    }),
                };
                await host.Client.SendAsync(request, TestContext.Current.CancellationToken);
            });
            await MeasureAsync("revoke (refresh token)", async () =>
            {
                var fresh = await host.SignInAsync(account.Id);
                counter.Reset();
                using var request = new HttpRequestMessage(HttpMethod.Post, "connect/revoke")
                {
                    Content = new FormUrlEncodedContent(new Dictionary<string, string>
                    {
                        ["token"] = fresh.RefreshToken!, ["token_type_hint"] = "refresh_token", ["client_id"] = TokenServerHost.BffClient, ["client_secret"] = TokenServerHost.BffSecret,
                    }),
                };
                await host.Client.SendAsync(request, TestContext.Current.CancellationToken);
            });
        }

        await MeasureScimAsync(MeasureAsync);

        var path = Environment.GetEnvironmentVariable("JEFFOPS_PROBE_REPORT") ?? Path.Combine(Path.GetTempPath(), "jeffops-roundtrips.md");
        await File.WriteAllTextAsync(path, report + Environment.NewLine + details, TestContext.Current.CancellationToken);
    }

    private static async Task MeasureScimAsync(Func<string, Func<Task>, Task> measure)
    {
        var database = TestDatabase.SqliteFile("probe-scim");
        try
        {
            await using var host = await TokenServerHost.StartAsync(configure: builder =>
            {
                builder.Services.AddScoped<ITenantMembershipProvisioner, RecordingMemberships>();
                new AuthenticationBuilder(builder.Services, builder.Configuration).AddEnterprise().UseTestDatabase(database);
                builder.Services.AddScoped<IEnterpriseDatabaseInitializer, SeedDomain>();
                builder.Services.AddAuthorizationBuilder()
                    .AddPolicy("auth.enterprise.manage", policy => policy.RequireAuthenticatedUser())
                    .AddPolicy("auth.enterprise.scim_tokens", policy => policy.RequireAuthenticatedUser());
            },
            map: app =>
            {
                app.MapJeffOpsEnterprise();
                app.MapJeffOpsScim();
            });
            host.Tenants.Tenants[Contoso] = new TenantInfo(Contoso, null, true);
            var admin = await host.CreateAccountAsync("admin@contoso.com");
            host.Tenants.Memberships.GetOrAdd(admin.Id, _ => []).Add(new TenantMembership(Contoso, null, null, AccessLevel.Tenant));
            var created = await host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.ScimTokenRoutes, (await host.SignInAsync(admin.Id)).AccessToken, JsonContent.Create(new { name = "probe" }));
            var token = (await created.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("token").GetString()!;

            async Task<HttpResponseMessage> ScimAsync(HttpMethod method, string path, string? body = null)
            {
                using var request = new HttpRequestMessage(method, $"scim/v2/{path}");
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                if (body is not null)
                {
                    request.Content = new StringContent(body, Encoding.UTF8, "application/scim+json");
                }

                return await host.Client.SendAsync(request, TestContext.Current.CancellationToken);
            }

            var users = new List<string>();
            for (var index = 0; index < 50; index++)
            {
                var response = await ScimAsync(HttpMethod.Post, "Users", $$"""{"userName":"user{{index}}@contoso.com","emails":[{"value":"user{{index}}@contoso.com"}]}""");
                users.Add((await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("id").GetString()!);
            }

            var groups = new List<string>();
            for (var index = 0; index < 5; index++)
            {
                var members = string.Join(',', users.Skip(index * 10).Take(10).Select(id => $$"""{"value":"{{id}}"}"""));
                var response = await ScimAsync(HttpMethod.Post, "Groups", $$"""{"displayName":"Group {{index}}","members":[{{members}}]}""");
                groups.Add((await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("id").GetString()!);
            }

            var counter = 0;
            await measure("SCIM GET Users (50, each in a group)", () => ScimAsync(HttpMethod.Get, "Users?count=50"));
            await measure("SCIM GET Users/{id}", () => ScimAsync(HttpMethod.Get, $"Users/{users[0]}"));
            await measure("SCIM GET Groups (5 × 10 members)", () => ScimAsync(HttpMethod.Get, "Groups"));
            await measure("SCIM GET Users filter userName eq", () => ScimAsync(HttpMethod.Get, "Users?filter=" + Uri.EscapeDataString("userName eq \"user7@contoso.com\"")));
            await measure("SCIM POST Users", () => ScimAsync(HttpMethod.Post, "Users", $$"""{"userName":"new{{Interlocked.Increment(ref counter)}}@contoso.com","emails":[{"value":"new{{counter}}@contoso.com"}]}"""));
            await measure("SCIM PATCH Users/{id} (displayName)", () => ScimAsync(HttpMethod.Patch, $"Users/{users[1]}", $$"""{"Operations":[{"op":"replace","path":"displayName","value":"Name {{Interlocked.Increment(ref counter)}}"}]}"""));
            await measure("SCIM PATCH Groups/{id} (add 1 member)", () => ScimAsync(HttpMethod.Patch, $"Groups/{groups[0]}", $$$"""{"Operations":[{"op":"add","path":"members","value":[{"value":"{{{users[40 + (Interlocked.Increment(ref counter) % 10)]}}}"}]}]}"""));
            await measure("SCIM POST Bulk (10 users)", () =>
            {
                var start = Interlocked.Add(ref counter, 10);
                var operations = string.Join(',', Enumerable.Range(start, 10).Select(index =>
                    $$$"""{"method":"POST","path":"/Users","bulkId":"b{{{index}}}","data":{"userName":"bulk{{{index}}}@contoso.com","emails":[{"value":"bulk{{{index}}}@contoso.com"}]}}"""));
                return ScimAsync(HttpMethod.Post, "Bulk", $$"""{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[{{operations}}]}""");
            });
            await measure("HRD discover (verified domain)", () => host.Client.GetAsync(new Uri("account/login/discover?email=jo%40contoso.com&returnUrl=%2F", UriKind.Relative), TestContext.Current.CancellationToken));
        }
        finally
        {
            TestDatabase.DeleteSqlite(database);
        }
    }

    private static async Task<string> CreatePatAsync(TokenServerHost host, string accessToken)
    {
        var response = await host.SendAsync(HttpMethod.Post, "account/pats", accessToken, JsonContent.Create(new { name = "probe", expiresInDays = 30 }));
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        return body.TryGetProperty("secret", out var secret) ? secret.GetString()! : throw new InvalidOperationException(body.ToString());
    }

    private sealed class SeedDomain(EnterpriseDbContext db) : IEnterpriseDatabaseInitializer
    {
        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            if (!await db.Domains.AnyAsync(cancellationToken))
            {
                var domain = Enterprise.Domain.TenantDomain.Claim(Contoso, "contoso.com", DateTimeOffset.UtcNow);
                domain.CheckTxtRecords([domain.ExpectedValue("v=")], "v=", DateTimeOffset.UtcNow);
                db.Domains.Add(domain);
                await db.SaveChangesAsync(cancellationToken);
            }
        }
    }
}

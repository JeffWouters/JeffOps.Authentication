using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.LocalAccounts.Application;
using JeffOps.Authentication.LocalAccounts.Domain;
using JeffOps.Authentication.LocalAccounts.Endpoints;
using JeffOps.Authentication.LocalAccounts.Infrastructure;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

public sealed partial class LocalAccountsTests : IAsyncDisposable
{
    private const string Password = "correct horse battery staple";

    private readonly string _database = Path.Combine(Path.GetTempPath(), $"jeffops-local-{Guid.NewGuid():N}.db");
    private readonly CapturingEmailSender _email = new();
    private TokenServerHost? _host;

    [Fact]
    public async Task A_registered_user_verifies_their_email_and_signs_in_with_a_password()
    {
        var host = await StartAsync();
        using var browser = new Browser(host);

        (await PostJsonAsync(host, "account/local/register", new { email = "ada@example.com", password = Password, displayName = "Ada" })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        (await LoginAsync(browser, "ada@example.com", Password)).ShouldContain("error=email_not_verified");

        (await PostJsonAsync(host, "account/local/verify-email", new { token = _email.TokenFor("ada@example.com", "verification") })).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await LoginAsync(browser, "ada@example.com", Password)).ShouldBe("/done");

        var tokens = await AuthorizeAsync(host, browser);
        tokens.Claims("amr").ShouldBe(["pwd"]);
    }

    [Fact]
    public async Task Wrong_passwords_and_unknown_emails_get_the_same_answer_and_lock_progressively()
    {
        var host = await StartAsync();
        using var browser = new Browser(host);
        await RegisterVerifiedAsync(host, "ada@example.com");

        (await LoginAsync(browser, "nobody@example.com", Password)).ShouldContain("error=invalid_credentials");
        for (var attempt = 0; attempt < 4; attempt++)
        {
            (await LoginAsync(browser, "ada@example.com", "wrong password!")).ShouldContain("error=invalid_credentials");
        }

        // The fourth failure locked the account for a while: even the right password waits.
        (await LoginAsync(browser, "ada@example.com", Password)).ShouldContain("error=locked_out");
        host.Time.Advance(TimeSpan.FromSeconds(3));
        (await LoginAsync(browser, "ada@example.com", Password)).ShouldBe("/done");
    }

    [Fact]
    public async Task Registering_a_taken_email_answers_the_same_and_tells_the_owner()
    {
        var host = await StartAsync();
        await RegisterVerifiedAsync(host, "ada@example.com");

        (await PostJsonAsync(host, "account/local/register", new { email = "ADA@example.com", password = "another password 1" })).StatusCode.ShouldBe(HttpStatusCode.Accepted);

        _email.Sent.ShouldContain(mail => mail.Email == "ada@example.com" && mail.Kind == "already-registered");
        (await PostJsonAsync(host, "account/local/register", new { email = "bob@example.com", password = "short" })).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task A_forgotten_password_is_reset_through_the_emailed_link_once()
    {
        var host = await StartAsync();
        using var browser = new Browser(host);
        await RegisterVerifiedAsync(host, "ada@example.com");

        (await PostJsonAsync(host, "account/local/password/forgot", new { email = "ada@example.com" })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        (await PostJsonAsync(host, "account/local/password/forgot", new { email = "nobody@example.com" })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var token = _email.TokenFor("ada@example.com", "reset");

        (await PostJsonAsync(host, "account/local/password/reset", new { token, newPassword = "a brand new passphrase" })).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await PostJsonAsync(host, "account/local/password/reset", new { token, newPassword = "yet another passphrase" })).StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        (await LoginAsync(browser, "ada@example.com", Password)).ShouldContain("error=invalid_credentials");
        (await LoginAsync(browser, "ada@example.com", "a brand new passphrase")).ShouldBe("/done");
    }

    [Fact]
    public async Task An_authenticator_app_makes_sign_in_multi_factor_and_codes_work_once()
    {
        var host = await StartAsync();
        using var browser = new Browser(host);
        await RegisterVerifiedAsync(host, "ada@example.com");
        (await LoginAsync(browser, "ada@example.com", Password)).ShouldBe("/done");
        var accessToken = (await AuthorizeAsync(host, browser)).AccessToken!;

        var setup = await (await host.SendAsync(HttpMethod.Post, "account/local/manage/authenticator", accessToken)).Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        var secret = Base32Decode(setup.GetProperty("secret").GetString()!);
        setup.GetProperty("otpAuthUri").GetString()!.ShouldStartWith("otpauth://totp/");

        var confirm = await host.SendAsync(HttpMethod.Post, "account/local/manage/authenticator/confirm", accessToken, JsonContent.Create(new { code = Totp.Code(secret, Totp.StepOf(host.Time.GetUtcNow())) }));
        confirm.StatusCode.ShouldBe(HttpStatusCode.OK, await confirm.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var recoveryCodes = (await confirm.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("recoveryCodes").EnumerateArray().Select(code => code.GetString()!).ToList();
        recoveryCodes.Count.ShouldBe(10);

        using var second = new Browser(host);
        (await LoginAsync(second, "ada@example.com", Password)).ShouldStartWith("/account/login/code");

        // The code used to confirm can't be replayed; the next one works.
        (await CodeAsync(second, Totp.Code(secret, Totp.StepOf(host.Time.GetUtcNow())))).ShouldContain("error=invalid_code");
        host.Time.Advance(TimeSpan.FromSeconds(30));
        (await CodeAsync(second, Totp.Code(secret, Totp.StepOf(host.Time.GetUtcNow())))).ShouldBe("/done");

        var tokens = await AuthorizeAsync(host, second);
        tokens.Claims("amr").ShouldBe(["pwd", "otp", "mfa"], ignoreOrder: true);
        tokens.Claims("step_up").ShouldBe(["mfa"]);

        using var third = new Browser(host);
        (await LoginAsync(third, "ada@example.com", Password)).ShouldStartWith("/account/login/code");
        (await CodeAsync(third, recoveryCodes[0], recovery: true)).ShouldBe("/done");
        using var fourth = new Browser(host);
        await LoginAsync(fourth, "ada@example.com", Password);
        (await CodeAsync(fourth, recoveryCodes[0], recovery: true)).ShouldContain("error=invalid_code");
    }

    [Fact]
    public async Task A_passkey_is_registered_from_a_stepped_up_session_and_signs_in_alone()
    {
        var host = await StartAsync(new()
        {
            ["JeffOps:TokenServer:Mfa:RequireForSensitiveActions"] = "false",
            ["JeffOps:LocalAccounts:PasskeyAllowedOrigins:0"] = "https://localhost",
        });
        using var browser = new Browser(host);
        var accountId = await RegisterVerifiedAsync(host, "ada@example.com");
        await LoginAsync(browser, "ada@example.com", Password);
        var accessToken = (await AuthorizeAsync(host, browser)).AccessToken!;
        using var authenticator = new SoftwareAuthenticator();

        var creation = await host.SendAsync(HttpMethod.Post, "account/local/manage/passkeys/options", accessToken);
        creation.StatusCode.ShouldBe(HttpStatusCode.OK, await creation.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var state = StateCookie(creation);
        var credential = authenticator.Create(await creation.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        using var add = new HttpRequestMessage(HttpMethod.Post, "account/local/manage/passkeys")
        {
            Content = new StringContent($$"""{"credential":{{credential}},"name":"Laptop"}""", Encoding.UTF8, "application/json"),
        };
        add.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        add.Headers.Add("Cookie", state);
        var added = await host.Client.SendAsync(add, TestContext.Current.CancellationToken);
        added.StatusCode.ShouldBe(HttpStatusCode.OK, await added.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        using var fresh = new Browser(host);
        var options = await fresh.SendAsync(new HttpRequestMessage(HttpMethod.Post, "account/local/passkey/login/options") { Content = JsonContent.Create(new { }) });
        options.StatusCode.ShouldBe(HttpStatusCode.OK);
        var assertion = authenticator.Get(await options.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), Encoding.UTF8.GetBytes(accountId.ToString()));
        var login = await fresh.SendAsync(new HttpRequestMessage(HttpMethod.Post, "account/local/passkey/login")
        {
            Content = new StringContent($$"""{"credential":{{assertion}},"returnUrl":"/done"}""", Encoding.UTF8, "application/json"),
        });
        login.StatusCode.ShouldBe(HttpStatusCode.OK, await login.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        var tokens = await AuthorizeAsync(host, fresh);
        tokens.Claims("amr").ShouldBe(["hwk", "user", "mfa"], ignoreOrder: true);
    }

    [Fact]
    public async Task Passkeys_need_a_stepped_up_session_to_be_added()
    {
        var host = await StartAsync();
        using var browser = new Browser(host);
        await RegisterVerifiedAsync(host, "ada@example.com");
        await LoginAsync(browser, "ada@example.com", Password);
        var accessToken = (await AuthorizeAsync(host, browser)).AccessToken!;

        var response = await host.SendAsync(HttpMethod.Post, "account/local/manage/passkeys/options", accessToken);

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Changing_the_password_signs_out_every_other_session()
    {
        var host = await StartAsync();
        await RegisterVerifiedAsync(host, "ada@example.com");
        using var laptop = new Browser(host);
        using var phone = new Browser(host);
        await LoginAsync(laptop, "ada@example.com", Password);
        await LoginAsync(phone, "ada@example.com", Password);
        var onLaptop = await AuthorizeAsync(host, laptop, "openid offline_access api");
        var onPhone = await AuthorizeAsync(host, phone, "openid offline_access api");

        var changed = await host.SendAsync(HttpMethod.Post, "account/local/manage/password", onLaptop.AccessToken,
            JsonContent.Create(new { currentPassword = Password, newPassword = "a completely new passphrase" }));
        changed.StatusCode.ShouldBe(HttpStatusCode.NoContent, await changed.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        (await host.RefreshAsync(onPhone.RefreshToken!)).Error.ShouldBe("invalid_grant");
        (await host.RefreshAsync(onLaptop.RefreshToken!)).Error.ShouldBe("invalid_grant");
    }

    [Fact]
    public async Task Local_accounts_are_off_unless_enabled_outside_development()
    {
        var host = await StartAsync(enabled: false);

        (await PostJsonAsync(host, "account/local/register", new { email = "ada@example.com", password = Password })).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    public async ValueTask DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.DisposeAsync();
        }

        SqliteConnection.ClearAllPools();
        try
        {
            File.Delete(_database);
        }
        catch (IOException)
        {
            // Best effort.
        }
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private async Task<TokenServerHost> StartAsync(Dictionary<string, string?>? overrides = null, bool enabled = true)
    {
        var connectionString = new SqliteConnectionStringBuilder { DataSource = _database, Pooling = false }.ToString();
        var settings = new Dictionary<string, string?>
        {
            ["JeffOps:LocalAccounts:HashIterations"] = "10000",
            ["JeffOps:LocalAccounts:PublicOrigin"] = "https://localhost/",
        };
        if (enabled)
        {
            settings["JeffOps:LocalAccounts:Enabled"] = "true";
        }

        foreach (var (key, value) in overrides ?? [])
        {
            settings[key] = value;
        }

        _host = await TokenServerHost.StartAsync(
            settings,
            configure: builder =>
            {
                builder.Services.AddSingleton(_email);
                builder.Services.AddScoped<ILocalAccountsDatabaseInitializer, CreateDatabase>();
                new AuthenticationBuilder(builder.Services, builder.Configuration)
                    .AddLocalAccounts()
                    .UseEmailSender<CapturingEmailSender.Scoped>()
                    .UseDatabase((_, options) => options.UseSqlite(connectionString));
            },
            cookieSignIn: true,
            map: app => app.MapJeffOpsLocalAccounts());
        return _host;
    }

    private async Task<Guid> RegisterVerifiedAsync(TokenServerHost host, string email)
    {
        (await PostJsonAsync(host, "account/local/register", new { email, password = Password })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        (await PostJsonAsync(host, "account/local/verify-email", new { token = _email.TokenFor(email, "verification") })).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        await using var scope = host.Services.CreateAsyncScope();
        return (await scope.ServiceProvider.GetRequiredService<Application.Abstractions.IAccountRepository>().FindByEmailAsync(email, TestContext.Current.CancellationToken))!.Id;
    }

    private static Task<HttpResponseMessage> PostJsonAsync(TokenServerHost host, string path, object body) =>
        host.SendAsync(HttpMethod.Post, path, null, JsonContent.Create(body));

    /// <summary>Posts the hosted login form (with its antiforgery token) and returns where it redirects.</summary>
    private static async Task<string> LoginAsync(Browser browser, string email, string password)
    {
        var page = await browser.GetAsync(null!, $"account/login?returnUrl=%2Fdone&email={Uri.EscapeDataString(email)}");
        var html = await page.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var form = new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = AntiforgeryToken().Match(html).Groups[1].Value,
            ["returnUrl"] = "/done",
            ["email"] = email,
            ["password"] = password,
        };

        var response = await browser.SendAsync(new HttpRequestMessage(HttpMethod.Post, "account/local/login") { Content = new FormUrlEncodedContent(form) });
        response.StatusCode.ShouldBe(HttpStatusCode.Redirect, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return response.Headers.Location!.OriginalString;
    }

    private static async Task<string> CodeAsync(Browser browser, string code, bool recovery = false)
    {
        var page = await browser.GetAsync(null!, "account/login/code?returnUrl=%2Fdone");
        var html = await page.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var form = new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = AntiforgeryToken().Match(html).Groups[1].Value,
            ["returnUrl"] = "/done",
            [recovery ? "recoveryCode" : "code"] = code,
        };

        var response = await browser.SendAsync(new HttpRequestMessage(HttpMethod.Post, "account/local/login/code") { Content = new FormUrlEncodedContent(form) });
        return response.Headers.Location!.OriginalString;
    }

    /// <summary>Runs the code flow with PKCE in the signed-in browser and redeems the code.</summary>
    private static async Task<TokenResponse> AuthorizeAsync(TokenServerHost host, Browser browser, string scope = "openid api")
    {
        var verifier = SoftwareAuthenticator.Base64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = SoftwareAuthenticator.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var authorize = await browser.GetAsync(null!,
            $"connect/authorize?client_id={TokenServerHost.BffClient}&response_type=code&redirect_uri={Uri.EscapeDataString(TokenServerHost.BffRedirect)}" +
            $"&scope={Uri.EscapeDataString(scope)}&code_challenge={challenge}&code_challenge_method=S256&state=xyz");
        authorize.StatusCode.ShouldBe(HttpStatusCode.Redirect);
        var code = TokenServerHost.QueryValue(authorize.Headers.Location!, "code").ShouldNotBeNull(authorize.Headers.Location!.ToString());

        var tokens = await host.TokenAsync(new()
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TokenServerHost.BffRedirect,
            ["code_verifier"] = verifier,
            ["client_id"] = TokenServerHost.BffClient,
            ["client_secret"] = TokenServerHost.BffSecret,
        });
        tokens.Status.ShouldBe(HttpStatusCode.OK, tokens.Body.ToString());
        return tokens;
    }

    private static string StateCookie(HttpResponseMessage response) =>
        response.Headers.GetValues("Set-Cookie").Single(cookie => cookie.StartsWith("jeffops-passkey=", StringComparison.Ordinal)).Split(';')[0];

    private static byte[] Base32Decode(string value)
    {
        const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new List<byte>();
        int buffer = 0, bits = 0;
        foreach (var character in value)
        {
            buffer = (buffer << 5) | Alphabet.IndexOf(character, StringComparison.Ordinal);
            bits += 5;
            if (bits >= 8)
            {
                output.Add((byte)(buffer >> (bits - 8)));
                bits -= 8;
            }
        }

        return [.. output];
    }

    [GeneratedRegex("<input[^>]*name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();

    private sealed class CreateDatabase(LocalAccountsDbContext db) : ILocalAccountsDatabaseInitializer
    {
        public Task InitializeAsync(CancellationToken cancellationToken) => db.Database.EnsureCreatedAsync(cancellationToken);
    }
}

internal sealed class CapturingEmailSender
{
    public ConcurrentQueue<(string Email, string Kind, Uri? Link)> Sent { get; } = new();

    public string TokenFor(string email, string kind) =>
        TokenServerHost.QueryValue(Sent.Last(mail => mail.Email == email && mail.Kind == kind).Link!, "token")!;

    internal sealed class Scoped(CapturingEmailSender sender) : IAccountEmailSender
    {
        public Task SendVerificationAsync(string email, Uri link, CancellationToken cancellationToken) => Add(email, "verification", link);

        public Task SendPasswordResetAsync(string email, Uri link, CancellationToken cancellationToken) => Add(email, "reset", link);

        public Task SendAlreadyRegisteredAsync(string email, CancellationToken cancellationToken) => Add(email, "already-registered", null);

        private Task Add(string email, string kind, Uri? link)
        {
            sender.Sent.Enqueue((email, kind, link));
            return Task.CompletedTask;
        }
    }
}

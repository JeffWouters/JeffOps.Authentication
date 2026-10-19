using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.LocalAccounts.Application;
using JeffOps.Authentication.LocalAccounts.Application.Features.SignIn;
using JeffOps.Authentication.LocalAccounts.Domain;
using JeffOps.Authentication.LocalAccounts.Endpoints;
using JeffOps.Authentication.LocalAccounts.Infrastructure;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace JeffOps.Authentication.Server.Tests;

public sealed partial class LocalAccountsTests : IAsyncDisposable
{
    private const string Password = "correct horse battery staple";

    private readonly string _database = TestDatabase.SqliteFile("local");
    private readonly CapturingEmailSender _email = new();
    private readonly BackchannelReceiver _backchannel = new();
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

        // The fourth failure locked the account for a while: even the right password waits, answered like a wrong one.
        (await LoginAsync(browser, "ada@example.com", Password)).ShouldContain("error=invalid_credentials");
        host.Time.Advance(TimeSpan.FromSeconds(3));
        (await LoginAsync(browser, "ada@example.com", Password)).ShouldBe("/done");
    }

    [Fact]
    public async Task Registering_a_taken_email_answers_the_same_and_tells_the_owner()
    {
        var host = await StartAsync();
        await RegisterVerifiedAsync(host, "ada@example.com");

        (await PostJsonAsync(host, "account/local/register", new { email = "ADA@example.com", password = "another password 1" })).StatusCode.ShouldBe(HttpStatusCode.Accepted);

        _email.WaitFor("ada@example.com", "already-registered");
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
        var onLaptop = await AuthorizeAsync(host, laptop, "openid offline_access account");
        var onPhone = await AuthorizeAsync(host, phone, "openid offline_access account");

        var changed = await host.SendAsync(HttpMethod.Post, "account/local/manage/password", onLaptop.AccessToken,
            JsonContent.Create(new { currentPassword = Password, newPassword = "a completely new passphrase" }));
        changed.StatusCode.ShouldBe(HttpStatusCode.NoContent, await changed.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        (await host.RefreshAsync(onPhone.RefreshToken!)).Error.ShouldBe("invalid_grant");
        (await host.RefreshAsync(onLaptop.RefreshToken!)).Error.ShouldBe("invalid_grant");
    }

    [Fact]
    public async Task Signing_out_ends_that_session_only_and_tells_clients_which_one()
    {
        var host = await StartAsync(new() { ["JeffOps:TokenServer:Clients:0:BackchannelLogoutUri"] = "https://bff.test/backchannel-logout" });
        var accountId = await RegisterVerifiedAsync(host, "ada@example.com");
        using var laptop = new Browser(host);
        using var phone = new Browser(host);
        await LoginAsync(laptop, "ada@example.com", Password);
        await LoginAsync(phone, "ada@example.com", Password);
        var onLaptop = await AuthorizeAsync(host, laptop, "openid offline_access account");
        var onPhone = await AuthorizeAsync(host, phone, "openid offline_access account");

        var laptopSession = new JsonWebToken(onLaptop.IdToken!).GetClaim("sid").Value;
        var phoneSession = new JsonWebToken(onPhone.IdToken!).GetClaim("sid").Value;
        laptopSession.ShouldNotBe(phoneSession, "each sign-in is its own session");
        onLaptop.Access.GetClaim("sid").Value.ShouldBe(laptopSession);

        // The client signs the laptop out, naming the session with its ID token.
        await laptop.GetAsync(null!, "connect/endsession?id_token_hint=" + Uri.EscapeDataString(onLaptop.IdToken!));

        // The client is told which session ended, so it drops that one only.
        var logout = new JsonWebToken(_backchannel.LogoutTokens.ShouldHaveSingleItem());
        logout.Subject.ShouldBe(accountId.ToString());
        logout.GetClaim("sid").Value.ShouldBe(laptopSession);

        // The laptop's session is over; the phone's continues, and keeps its session id across refreshes.
        (await host.RefreshAsync(onLaptop.RefreshToken!)).Error.ShouldBe("invalid_grant");
        var refreshed = await host.RefreshAsync(onPhone.RefreshToken!);
        refreshed.Status.ShouldBe(HttpStatusCode.OK, refreshed.Body.ToString());
        new JsonWebToken(refreshed.IdToken!).GetClaim("sid").Value.ShouldBe(phoneSession);
    }

    [Fact]
    public async Task With_email_codes_a_password_sign_in_completes_with_the_code_sent_by_email()
    {
        var host = await StartAsync(new() { ["JeffOps:LocalAccounts:EmailCodes"] = "true" });
        await RegisterVerifiedAsync(host, "ada@example.com");
        using var browser = new Browser(host);

        (await LoginAsync(browser, "ada@example.com", Password)).ShouldContain("method=email");
        var (to, code) = _email.Codes.ShouldHaveSingleItem();
        to.ShouldBe("ada@example.com");
        code.Length.ShouldBe(6);

        var wrong = code == "000000" ? "111111" : "000000";
        (await CodeAsync(browser, wrong, method: "email")).ShouldContain("error=invalid_code");
        (await CodeAsync(browser, code, method: "email")).ShouldBe("/done");

        var tokens = await AuthorizeAsync(host, browser);
        tokens.Claims("amr").ShouldContain("mfa");

        // A code works once.
        using var again = new Browser(host);
        await LoginAsync(again, "ada@example.com", Password);
        (await CodeAsync(again, code, method: "email")).ShouldContain("error=invalid_code");
    }

    [Fact]
    public async Task A_forgotten_password_is_reset_through_the_hosted_pages()
    {
        var host = await StartAsync();
        await RegisterVerifiedAsync(host, "ada@example.com");
        using var browser = new Browser(host);

        var requested = await SubmitAsync(browser, "account/forgot-password", "account/local/password/forgot/form", new() { ["email"] = "ada@example.com" });
        requested.Headers.Location!.OriginalString.ShouldBe("/account/forgot-password?sent=1");
        var unknown = await SubmitAsync(browser, "account/forgot-password", "account/local/password/forgot/form", new() { ["email"] = "nobody@example.com" });
        unknown.Headers.Location!.OriginalString.ShouldBe("/account/forgot-password?sent=1", "the same answer for unknown addresses");

        var token = _email.TokenFor("ada@example.com", "reset");
        var weak = await SubmitAsync(browser, $"account/reset-password?token={token}", "account/local/password/reset/form", new() { ["token"] = token, ["password"] = "short" });
        weak.Headers.Location!.OriginalString.ShouldContain("error=weak_password");

        var reset = await SubmitAsync(browser, $"account/reset-password?token={token}", "account/local/password/reset/form", new() { ["token"] = token, ["password"] = "a completely new passphrase" });
        reset.Headers.Location!.OriginalString.ShouldBe("/account/reset-password?done=1");
        (await LoginAsync(browser, "ada@example.com", "a completely new passphrase")).ShouldBe("/done");
    }

    [Fact]
    public async Task An_email_is_verified_through_the_hosted_page_only_when_the_button_is_pressed()
    {
        var host = await StartAsync();
        (await PostJsonAsync(host, "account/local/register", new { email = "ada@example.com", password = Password })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var token = _email.TokenFor("ada@example.com", "verification");
        using var browser = new Browser(host);

        // Opening the link (as a mail scanner would) verifies nothing; the form does.
        await browser.GetAsync(null!, $"account/verify-email?token={token}");
        (await LoginAsync(browser, "ada@example.com", Password)).ShouldContain("error=email_not_verified");

        var verified = await SubmitAsync(browser, $"account/verify-email?token={token}", "account/local/verify-email/form", new() { ["token"] = token });
        verified.Headers.Location!.OriginalString.ShouldBe("/account/verify-email?done=1");
        (await LoginAsync(browser, "ada@example.com", Password)).ShouldBe("/done");
    }

    [Fact]
    public async Task Local_accounts_are_off_unless_enabled_outside_development()
    {
        var host = await StartAsync(enabled: false);

        (await PostJsonAsync(host, "account/local/register", new { email = "ada@example.com", password = Password })).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    public async ValueTask DisposeAsync()
    {
        _email.Gate?.TrySetResult();
        if (_host is not null)
        {
            await _host.DisposeAsync();
        }

        TestDatabase.DeleteSqlite(_database);
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Every_wrong_password_in_a_parallel_burst_counts_towards_lockout()
    {
        var host = await StartAsync();
        await RegisterVerifiedAsync(host, "ada@example.com");

        // The login form answers a refused guess like a wrong one, so the burst runs against the handler, which tells them apart.
        var outcomes = await Task.WhenAll(Enumerable.Range(0, 12).Select(async _ =>
        {
            await using var attempt = host.Services.CreateAsyncScope();
            var handler = attempt.ServiceProvider.GetRequiredService<ICommandHandler<PasswordSignInCommand, LocalSignInResult>>();
            return (await handler.HandleAsync(new PasswordSignInCommand("ada@example.com", "a wrong passphrase guess"), TestContext.Current.CancellationToken)).Value.Status;
        }));

        // A guess that was checked (Failed) was counted first; the rest were refused unchecked.
        var checkedGuesses = outcomes.Count(status => status == LocalSignInStatus.Failed);
        await using var scope = host.Services.CreateAsyncScope();
        var accountId = (await scope.ServiceProvider.GetRequiredService<Application.Abstractions.IAccountRepository>().FindByEmailAsync("ada@example.com", TestContext.Current.CancellationToken))!.Id;
        var credential = (await scope.ServiceProvider.GetRequiredService<ILocalCredentialRepository>().FindAsync(accountId, TestContext.Current.CancellationToken))!;
        credential.FailedAttempts.ShouldBeGreaterThanOrEqualTo(checkedGuesses);
        checkedGuesses.ShouldBeLessThanOrEqualTo(4, "the lockout stops the burst after a few checked guesses");
    }

    [Fact]
    public async Task With_email_codes_a_correct_password_doesn_t_reset_the_count_and_codes_are_capped()
    {
        var host = await StartAsync(new() { ["JeffOps:LocalAccounts:EmailCodes"] = "true" });
        await RegisterVerifiedAsync(host, "ada@example.com");

        for (var round = 0; round < 8; round++)
        {
            using var browser = new Browser(host);
            await LoginAsync(browser, "ada@example.com", Password);
            host.Time.Advance(TimeSpan.FromMinutes(2));
        }

        _email.Codes.Count.ShouldBe(5, "at most five codes an hour");

        await using var scope = host.Services.CreateAsyncScope();
        var accountId = (await scope.ServiceProvider.GetRequiredService<Application.Abstractions.IAccountRepository>().FindByEmailAsync("ada@example.com", TestContext.Current.CancellationToken))!.Id;
        var credential = (await scope.ServiceProvider.GetRequiredService<ILocalCredentialRepository>().FindAsync(accountId, TestContext.Current.CancellationToken))!;
        credential.FailedAttempts.ShouldBeGreaterThan(0, "the attempts stand until the emailed code is entered");
    }

    [Fact]
    public async Task After_signing_out_the_session_s_access_tokens_no_longer_reach_the_account_apis()
    {
        var host = await StartAsync();
        await RegisterVerifiedAsync(host, "ada@example.com");
        using var browser = new Browser(host);
        await LoginAsync(browser, "ada@example.com", Password);
        var tokens = await AuthorizeAsync(host, browser, "openid account");
        (await host.SendAsync(HttpMethod.Get, "account/pats", tokens.AccessToken)).StatusCode.ShouldBe(HttpStatusCode.OK);

        await browser.GetAsync(null!, "connect/endsession?id_token_hint=" + Uri.EscapeDataString(tokens.IdToken!));

        // The access token hasn't expired, but its session is over: no new personal access tokens from it, nothing else either.
        (await host.SendAsync(HttpMethod.Get, "account/pats", tokens.AccessToken)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_sign_out_link_from_another_site_asks_first()
    {
        var host = await StartAsync();
        await RegisterVerifiedAsync(host, "ada@example.com");
        using var browser = new Browser(host);
        await LoginAsync(browser, "ada@example.com", Password);
        var tokens = await AuthorizeAsync(host, browser, "openid offline_access");

        // A link or image on another site: nothing ends, the user is asked.
        var asked = await browser.GetAsync(null!, "connect/endsession?state=xyz");
        asked.Headers.Location!.OriginalString.ShouldStartWith("/account/logout?");
        (await host.RefreshAsync(tokens.RefreshToken!)).Status.ShouldBe(HttpStatusCode.OK);

        // The user confirms on the page: signed out.
        var page = await (await browser.GetAsync(null!, asked.Headers.Location.OriginalString)).Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        page.ShouldContain("name=\"state\" value=\"xyz\"");
        var confirmed = await browser.SendAsync(new HttpRequestMessage(HttpMethod.Post, "connect/endsession")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = AntiforgeryToken().Match(page).Groups[1].Value,
                ["state"] = "xyz",
                ["confirm"] = "yes",
            }),
        });
        confirmed.Headers.Location!.OriginalString.ShouldNotStartWith("/account/logout");
        (await host.RefreshAsync(tokens.RefreshToken!)).Error.ShouldBe("invalid_grant");
    }

    [Fact]
    public async Task Sign_in_attempts_for_one_account_are_rate_limited()
    {
        var host = await StartAsync(new() { ["JeffOps:RateLimiting:SignInPerAccount:PermitLimit"] = "3" });
        await RegisterVerifiedAsync(host, "ada@example.com");

        for (var attempt = 0; attempt < 3; attempt++)
        {
            using var browser = new Browser(host);
            (await LoginAsync(browser, "ada@example.com", "a wrong passphrase guess")).ShouldContain("error=invalid_credentials");
        }

        using (var browser = new Browser(host))
        {
            (await LoginAsync(browser, "ADA@example.com", Password)).ShouldContain("error=too_many_requests", customMessage: "the same account, however written");
        }

        // A minute later the account may try again; other accounts never waited.
        host.Time.Advance(TimeSpan.FromMinutes(1));
        using (var browser = new Browser(host))
        {
            (await LoginAsync(browser, "ada@example.com", Password)).ShouldNotContain("error=");
        }
    }

    [Fact]
    public async Task Requests_that_send_mail_to_one_address_are_rate_limited()
    {
        var host = await StartAsync(new() { ["JeffOps:RateLimiting:MailPerRecipient:PermitLimit"] = "2" });
        await RegisterVerifiedAsync(host, "ada@example.com");   // registering mailed ada once

        (await PostJsonAsync(host, "account/local/password/forgot", new { email = "ada@example.com" })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var limited = await PostJsonAsync(host, "account/local/password/forgot", new { email = "ada@example.com" });
        limited.StatusCode.ShouldBe(HttpStatusCode.TooManyRequests);
        limited.Headers.RetryAfter.ShouldNotBeNull();
        (await PostJsonAsync(host, "account/local/password/forgot", new { email = "bea@example.com" })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
    }

    // ---- Security review proofs (docs/security-review.md) ---------------------------------------------------------------

    [Fact]
    public async Task A_token_exchanged_from_a_pat_can_t_manage_the_accounts_credentials()
    {
        // LA-1: a PAT without a ceiling yields a token with cred=pat but no pat_perm; it must not count as the user's session.
        var host = await StartAsync(new() { ["JeffOps:TokenServer:Mfa:RequireForSensitiveActions"] = "false" });
        using var browser = new Browser(host);
        await RegisterVerifiedAsync(host, "ada@example.com");
        await LoginAsync(browser, "ada@example.com", Password);
        var session = (await AuthorizeAsync(host, browser)).AccessToken!;
        var created = await host.SendAsync(HttpMethod.Post, "account/pats", session, JsonContent.Create(new JeffOps.Authentication.Abstractions.Contracts.CreatePersonalAccessTokenRequest("ci")));
        created.StatusCode.ShouldBe(HttpStatusCode.OK, await created.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var secret = (await created.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("secret").GetString()!;
        var fromPat = (await host.ExchangePatAsync(secret, scope: "account")).AccessToken!;

        var enroll = await host.SendAsync(HttpMethod.Post, "account/local/manage/authenticator", fromPat);

        enroll.StatusCode.ShouldBe(HttpStatusCode.Forbidden, await enroll.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task The_account_apis_refuse_an_access_token_issued_for_another_audience()
    {
        // LA-2 / DEL-2: a token whose only audience is a resource API ("api") was meant for that API, not the token server.
        var host = await StartAsync(new() { ["JeffOps:TokenServer:Mfa:RequireForSensitiveActions"] = "false" });
        using var browser = new Browser(host);
        await RegisterVerifiedAsync(host, "ada@example.com");
        await LoginAsync(browser, "ada@example.com", Password);
        var forApi = await AuthorizeAsync(host, browser, scope: "api");
        forApi.Access.Audiences.ShouldBe(["api"]);

        var response = await host.SendAsync(HttpMethod.Post, "account/pats", forApi.AccessToken!, JsonContent.Create(new JeffOps.Authentication.Abstractions.Contracts.CreatePersonalAccessTokenRequest("ci")));

        response.StatusCode.ShouldBeOneOf([HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden], await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task A_locked_account_answers_like_an_unknown_email_and_the_answer_never_names_the_address()
    {
        // LA-7: locked_out told which addresses have accounts, and the redirect carried the address.
        var host = await StartAsync();
        using var browser = new Browser(host);
        await RegisterVerifiedAsync(host, "ada@example.com");
        for (var attempt = 0; attempt < 4; attempt++)
        {
            await LoginAsync(browser, "ada@example.com", "wrong password!");
        }

        var locked = await LoginAsync(browser, "ada@example.com", Password);
        var unknown = await LoginAsync(browser, "nobody@example.com", Password);

        locked.ShouldBe(unknown);
        locked.ShouldNotContain("example.com", Case.Insensitive);
        locked.ShouldNotContain("email=", Case.Insensitive);
        host.Time.Advance(TimeSpan.FromSeconds(3));
        (await LoginAsync(browser, "ada@example.com", Password)).ShouldBe("/done", "the lockout held, and lifted");
    }

    [Fact]
    public async Task Requests_that_email_an_address_answer_without_waiting_for_the_mail_server()
    {
        // LA-7: sending happened during the request, so a slow answer meant the address has an account.
        var host = await StartAsync();
        await RegisterVerifiedAsync(host, "ada@example.com");
        _email.Gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var answers = await Task.WhenAll(
            PostJsonAsync(host, "account/local/password/forgot", new { email = "ada@example.com" }),
            PostJsonAsync(host, "account/local/register", new { email = "bea@example.com", password = Password }))
            .WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);

        answers.ShouldAllBe(answer => answer.StatusCode == HttpStatusCode.Accepted);
        _email.Sent.ShouldNotContain(mail => mail.Kind == "reset", "the mail server hasn't answered yet");
        _email.Gate.SetResult();
        _email.TokenFor("ada@example.com", "reset").ShouldNotBeNullOrEmpty();
        _email.TokenFor("bea@example.com", "verification").ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public async Task Step_up_lapses_once_the_multi_factor_sign_in_is_older_than_the_maximum_age()
    {
        // LA-8: one multi-factor sign-in covered sensitive actions for the whole session.
        var host = await StartAsync(new() { ["JeffOps:TokenServer:AccessTokenLifetime"] = "01:00:00" });
        var accountId = await RegisterVerifiedAsync(host, "ada@example.com");
        var tokens = await host.SignInAsync(accountId, multiFactor: true);
        tokens.Claims("step_up").ShouldBe(["mfa"]);
        (await host.SendAsync(HttpMethod.Post, "account/local/manage/passkeys/options", tokens.AccessToken)).StatusCode.ShouldBe(HttpStatusCode.OK);

        host.Time.Advance(TimeSpan.FromMinutes(16));

        // The token still says step_up, but its sign-in is too old for the token server's own sensitive actions...
        var stale = await host.SendAsync(HttpMethod.Post, "account/local/manage/passkeys/options", tokens.AccessToken);
        stale.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        stale.Headers.WwwAuthenticate.ToString().ShouldContain("max_age=900");

        // ...and tokens issued from now on don't say it at all.
        var refreshed = await host.RefreshAsync(tokens.RefreshToken!);
        refreshed.Status.ShouldBe(HttpStatusCode.OK, refreshed.Body.ToString());
        refreshed.Claims("step_up").ShouldBeEmpty();
        refreshed.Claims("amr").ShouldContain("mfa");
    }

    [Fact]
    public async Task Local_registration_follows_the_email_domain_allow_list()
    {
        // LA-10: self-registration ignored AllowedEmailDomains and OpenRegistration.
        var host = await StartAsync(new()
        {
            ["JeffOps:TokenServer:Federation:OpenRegistration"] = "false",
            ["JeffOps:TokenServer:Federation:AllowedEmailDomains:0"] = "example.com",
        });

        (await PostJsonAsync(host, "account/local/register", new { email = "ada@example.com", password = Password })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var elsewhere = await PostJsonAsync(host, "account/local/register", new { email = "eve@elsewhere.test", password = Password });

        elsewhere.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await elsewhere.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("code").GetString().ShouldBe("domain_not_allowed");
        (await host.FindAccountAsync("eve@elsewhere.test")).ShouldBeNull();
    }

    [Fact]
    public async Task Local_registration_is_closed_outside_development_unless_opened()
    {
        var host = await StartAsync(new() { ["JeffOps:TokenServer:Federation:OpenRegistration"] = "false" });

        var response = await PostJsonAsync(host, "account/local/register", new { email = "ada@example.com", password = Password });

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("code").GetString().ShouldBe("registration_closed");
    }

    [Fact]
    public async Task The_second_factor_cookie_is_host_only_and_a_password_reset_ends_the_pending_sign_in()
    {
        // LA-11: the cookie lacked __Host-, and a pending second-factor step outlived a password reset.
        var host = await StartAsync();
        var accountId = await RegisterVerifiedAsync(host, "ada@example.com");
        var secret = await EnrolAuthenticatorAsync(host, (await host.SignInAsync(accountId)).AccessToken!);
        using var browser = new Browser(host);

        var login = await LoginResponseAsync(browser, "ada@example.com", Password);
        login.Headers.Location!.OriginalString.ShouldStartWith("/account/login/code");
        var cookie = login.Headers.GetValues("Set-Cookie").Single(header => header.Contains("jeffops-2fa", StringComparison.Ordinal));
        cookie.ShouldStartWith("__Host-jeffops-2fa=");
        cookie.ShouldContain("secure", Case.Insensitive);
        cookie.ShouldContain("path=/;", Case.Insensitive);
        cookie.ShouldNotContain("domain=", Case.Insensitive);

        (await PostJsonAsync(host, "account/local/password/forgot", new { email = "ada@example.com" })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        (await PostJsonAsync(host, "account/local/password/reset", new { token = _email.TokenFor("ada@example.com", "reset"), newPassword = "a brand new passphrase" })).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        host.Time.Advance(TimeSpan.FromSeconds(30));

        (await CodeAsync(browser, Totp.Code(secret, Totp.StepOf(host.Time.GetUtcNow())))).ShouldContain("error=signin_expired");
        (await CredentialAsync(host, accountId)).TotpEnabled.ShouldBeTrue("a reset of a verified account keeps its authenticator");
    }

    [Fact]
    public async Task A_reset_that_verifies_the_email_removes_what_was_enrolled_before()
    {
        // LA-12: whoever registered an address they don't own could enrol an authenticator and passkeys that outlived the
        // owner's reset.
        var host = await StartAsync(new()
        {
            ["JeffOps:LocalAccounts:RequireVerifiedEmail"] = "false",
            ["JeffOps:LocalAccounts:PasskeyAllowedOrigins:0"] = "https://localhost",
        });
        (await PostJsonAsync(host, "account/local/register", new { email = "ada@example.com", password = Password })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        var accountId = (await host.FindAccountAsync("ada@example.com"))!.Id;
        var accessToken = (await host.SignInAsync(accountId)).AccessToken!;
        await EnrolAuthenticatorAsync(host, accessToken);
        using var authenticator = new SoftwareAuthenticator();
        await AddPasskeyAsync(host, accessToken, authenticator);
        (await CredentialAsync(host, accountId)).Passkeys.Count.ShouldBe(1);

        (await PostJsonAsync(host, "account/local/password/forgot", new { email = "ada@example.com" })).StatusCode.ShouldBe(HttpStatusCode.Accepted);
        (await PostJsonAsync(host, "account/local/password/reset", new { token = _email.TokenFor("ada@example.com", "reset"), newPassword = "a brand new passphrase" })).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var credential = await CredentialAsync(host, accountId);
        credential.TotpEnabled.ShouldBeFalse();
        credential.ProtectedTotpSecret.ShouldBeNull();
        credential.RecoveryCodes.ShouldBeEmpty();
        credential.Passkeys.ShouldBeEmpty();
        (await host.FindAccountAsync("ada@example.com"))!.EmailVerified.ShouldBeTrue();
    }

    [Fact]
    public async Task A_passkey_doesn_t_sign_in_an_account_whose_email_is_unverified()
    {
        // LA-12: passkey sign-in ignored RequireVerifiedEmail.
        var host = await StartAsync(new() { ["JeffOps:LocalAccounts:PasskeyAllowedOrigins:0"] = "https://localhost" });
        var account = await host.CreateAccountAsync("ada@example.com", emailVerified: false);
        using var authenticator = new SoftwareAuthenticator();
        await AddPasskeyAsync(host, (await host.SignInAsync(account.Id)).AccessToken!, authenticator);

        using var browser = new Browser(host);
        var options = await browser.SendAsync(new HttpRequestMessage(HttpMethod.Post, "account/local/passkey/login/options") { Content = JsonContent.Create(new { }) });
        var assertion = authenticator.Get(await options.Content.ReadAsStringAsync(TestContext.Current.CancellationToken), Encoding.UTF8.GetBytes(account.Id.ToString()));
        var login = await browser.SendAsync(new HttpRequestMessage(HttpMethod.Post, "account/local/passkey/login")
        {
            Content = new StringContent($$"""{"credential":{{assertion}},"returnUrl":"/done"}""", Encoding.UTF8, "application/json"),
        });

        login.StatusCode.ShouldBe(HttpStatusCode.Forbidden, await login.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        (await login.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("code").GetString().ShouldBe("email_not_verified");
    }

    private async Task<TokenServerHost> StartAsync(Dictionary<string, string?>? overrides = null, bool enabled = true)
    {
        var settings = new Dictionary<string, string?>
        {
            ["JeffOps:LocalAccounts:HashIterations"] = "10000",
            ["JeffOps:LocalAccounts:PublicOrigin"] = "https://localhost/",
            ["JeffOps:TokenServer:Federation:OpenRegistration"] = "true",
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
                builder.Services.AddHttpClient("JeffOps.BackchannelLogout").ConfigurePrimaryHttpMessageHandler(() => _backchannel);
                new AuthenticationBuilder(builder.Services, builder.Configuration)
                    .AddLocalAccounts()
                    .UseEmailSender<CapturingEmailSender.Scoped>()
                    .UseTestDatabase(_database);
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

    private static async Task<LocalCredential> CredentialAsync(TokenServerHost host, Guid accountId)
    {
        await using var scope = host.Services.CreateAsyncScope();
        return (await scope.ServiceProvider.GetRequiredService<ILocalCredentialRepository>().FindAsync(accountId, TestContext.Current.CancellationToken))!;
    }

    /// <summary>Enrols an authenticator app with the session's access token; returns its secret.</summary>
    private static async Task<byte[]> EnrolAuthenticatorAsync(TokenServerHost host, string accessToken)
    {
        var setup = await (await host.SendAsync(HttpMethod.Post, "account/local/manage/authenticator", accessToken)).Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        var secret = Base32Decode(setup.GetProperty("secret").GetString()!);
        var confirm = await host.SendAsync(HttpMethod.Post, "account/local/manage/authenticator/confirm", accessToken, JsonContent.Create(new { code = Totp.Code(secret, Totp.StepOf(host.Time.GetUtcNow())) }));
        confirm.StatusCode.ShouldBe(HttpStatusCode.OK, await confirm.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return secret;
    }

    /// <summary>Registers a passkey of <paramref name="authenticator"/> with the (stepped-up) session's access token.</summary>
    private static async Task AddPasskeyAsync(TokenServerHost host, string accessToken, SoftwareAuthenticator authenticator)
    {
        var creation = await host.SendAsync(HttpMethod.Post, "account/local/manage/passkeys/options", accessToken);
        creation.StatusCode.ShouldBe(HttpStatusCode.OK, await creation.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        var credential = authenticator.Create(await creation.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        using var add = new HttpRequestMessage(HttpMethod.Post, "account/local/manage/passkeys")
        {
            Content = new StringContent($$"""{"credential":{{credential}},"name":"Laptop"}""", Encoding.UTF8, "application/json"),
        };
        add.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        add.Headers.Add("Cookie", StateCookie(creation));
        var added = await host.Client.SendAsync(add, TestContext.Current.CancellationToken);
        added.StatusCode.ShouldBe(HttpStatusCode.OK, await added.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    private static Task<HttpResponseMessage> PostJsonAsync(TokenServerHost host, string path, object body) =>
        host.SendAsync(HttpMethod.Post, path, null, JsonContent.Create(body));

    /// <summary>Posts the hosted login form (with its antiforgery token) and returns where it redirects.</summary>
    private static async Task<string> LoginAsync(Browser browser, string email, string password) =>
        (await LoginResponseAsync(browser, email, password)).Headers.Location!.OriginalString;

    private static async Task<HttpResponseMessage> LoginResponseAsync(Browser browser, string email, string password)
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
        return response;
    }

    /// <summary>Opens a hosted page and submits its form (with the page's antiforgery token) to <paramref name="action"/>.</summary>
    private static async Task<HttpResponseMessage> SubmitAsync(Browser browser, string page, string action, Dictionary<string, string> fields)
    {
        var html = await (await browser.GetAsync(null!, page)).Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        html.ShouldContain($"action=\"/{action}\"");
        fields["__RequestVerificationToken"] = AntiforgeryToken().Match(html).Groups[1].Value;
        return await browser.SendAsync(new HttpRequestMessage(HttpMethod.Post, action) { Content = new FormUrlEncodedContent(fields) });
    }

    private static async Task<string> CodeAsync(Browser browser, string code, bool recovery = false, string method = "authenticator")
    {
        var page = await browser.GetAsync(null!, $"account/login/code?returnUrl=%2Fdone&method={method}");
        var html = await page.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        var form = new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = AntiforgeryToken().Match(html).Groups[1].Value,
            ["returnUrl"] = "/done",
            [recovery ? "recoveryCode" : "code"] = code,
            ["method"] = method,
        };

        var response = await browser.SendAsync(new HttpRequestMessage(HttpMethod.Post, "account/local/login/code") { Content = new FormUrlEncodedContent(form) });
        return response.Headers.Location!.OriginalString;
    }

    /// <summary>Runs the code flow with PKCE in the signed-in browser and redeems the code.</summary>
    private static async Task<TokenResponse> AuthorizeAsync(TokenServerHost host, Browser browser, string scope = "openid account")
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
        response.Headers.GetValues("Set-Cookie").Single(cookie => cookie.StartsWith("__Host-jeffops-passkey=", StringComparison.Ordinal)).Split(';')[0];

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

    /// <summary>A client's back-channel logout endpoint: records the logout tokens it receives.</summary>
    private sealed class BackchannelReceiver : HttpMessageHandler
    {
        public System.Collections.Concurrent.ConcurrentQueue<string> LogoutTokens { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var form = System.Web.HttpUtility.ParseQueryString(await request.Content!.ReadAsStringAsync(cancellationToken));
            LogoutTokens.Enqueue(form["logout_token"]!);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    [GeneratedRegex("<input[^>]*name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryToken();
}

internal sealed class CapturingEmailSender
{
    public ConcurrentQueue<(string Email, string Kind, Uri? Link)> Sent { get; } = new();

    public ConcurrentQueue<(string Email, string Code)> Codes { get; } = new();

    /// <summary>While set, sending waits for it, as a slow mail server would.</summary>
    public TaskCompletionSource? Gate { get; set; }

    public string TokenFor(string email, string kind) =>
        TokenServerHost.QueryValue(WaitFor(email, kind).Link!, "token")!;

    /// <summary>The last mail of <paramref name="kind"/> to <paramref name="email"/>, waiting for it: mail is sent in the background.</summary>
    public (string Email, string Kind, Uri? Link) WaitFor(string email, string kind)
    {
        SpinWait.SpinUntil(() => Sent.Any(mail => mail.Email == email && mail.Kind == kind), TimeSpan.FromSeconds(10)).ShouldBeTrue($"no {kind} email to {email}");
        return Sent.Last(mail => mail.Email == email && mail.Kind == kind);
    }

    internal sealed class Scoped(CapturingEmailSender sender) : IAccountEmailSender
    {
        public Task SendVerificationAsync(string email, Uri link, CancellationToken cancellationToken) => Add(email, "verification", link, cancellationToken);

        public Task SendPasswordResetAsync(string email, Uri link, CancellationToken cancellationToken) => Add(email, "reset", link, cancellationToken);

        public Task SendAlreadyRegisteredAsync(string email, CancellationToken cancellationToken) => Add(email, "already-registered", null, cancellationToken);

        public Task SendSignInCodeAsync(string email, string code, CancellationToken cancellationToken)
        {
            sender.Codes.Enqueue((email, code));
            return Task.CompletedTask;
        }

        private async Task Add(string email, string kind, Uri? link, CancellationToken cancellationToken)
        {
            if (sender.Gate is { } gate)
            {
                await gate.Task.WaitAsync(cancellationToken);
            }

            sender.Sent.Enqueue((email, kind, link));
        }
    }
}

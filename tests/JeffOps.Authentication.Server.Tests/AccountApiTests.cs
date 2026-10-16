using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Contracts;
using JeffOps.Authentication.Infrastructure.Keys;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

public sealed class PersonalAccessTokenTests
{
    private static async Task<CreatePersonalAccessTokenResponse> CreatePatAsync(TokenServerHost server, string accessToken, CreatePersonalAccessTokenRequest request)
    {
        var response = await server.SendAsync(HttpMethod.Post, "account/pats", accessToken, JsonContent.Create(request));
        response.StatusCode.ShouldBe(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return (await response.Content.ReadFromJsonAsync<CreatePersonalAccessTokenResponse>(TestContext.Current.CancellationToken))!;
    }

    private static async Task<string?> ProblemCodeAsync(HttpResponseMessage response)
    {
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return body.RootElement.TryGetProperty("code", out var code) ? code.GetString() : null;
    }

    [Fact]
    public async Task A_pat_is_exchanged_for_a_short_lived_token_with_its_ceiling()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var tenant = server.Tenants.AddMembership(account.Id);
        var session = await server.SignInAsync(account.Id);

        var pat = await CreatePatAsync(server, session.AccessToken!, new("ci", 7, ["reports.read"]));
        pat.Secret.ShouldStartWith("pat_");

        var exchanged = await server.ExchangePatAsync(pat.Secret);

        exchanged.Status.ShouldBe(HttpStatusCode.OK, exchanged.Body.ToString());
        exchanged.RefreshToken.ShouldBeNull();
        exchanged.Claims("pat_perm").ShouldBe(["reports.read"]);
        exchanged.Claims("cred").ShouldBe(["pat"]);
        exchanged.Claims("tid").ShouldBe([tenant.ToString()]);
        exchanged.Claims("step_up").ShouldBeEmpty("a PAT is not stepped up unless created for sensitive actions");
        (exchanged.Access.ValidTo - exchanged.Access.IssuedAt).ShouldBe(TimeSpan.FromMinutes(15), TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task A_pat_for_sensitive_actions_is_stepped_up()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var session = await server.SignInAsync(account.Id);

        var pat = await CreatePatAsync(server, session.AccessToken!, new("deploy", AllowSensitiveActions: true));

        (await server.ExchangePatAsync(pat.Secret)).Claims("step_up").ShouldBe(["mfa"]);
    }

    [Fact]
    public async Task A_revoked_pat_no_longer_exchanges()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var session = await server.SignInAsync(account.Id);
        var pat = await CreatePatAsync(server, session.AccessToken!, new("ci"));

        (await server.SendAsync(HttpMethod.Delete, $"account/pats/{pat.Id}", session.AccessToken)).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var exchanged = await server.ExchangePatAsync(pat.Secret);
        exchanged.Error.ShouldBe("invalid_grant");
        exchanged.Code.ShouldBe("token_invalid");
    }

    [Fact]
    public async Task A_pat_stops_at_the_maximum_lifetime_even_if_lowered_later()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var session = await server.SignInAsync(account.Id);
        var pat = await CreatePatAsync(server, session.AccessToken!, new("ci", 90));

        server.Time.Advance(TimeSpan.FromDays(91));

        (await server.ExchangePatAsync(pat.Secret)).Code.ShouldBe("token_invalid");
    }

    [Fact]
    public async Task Pats_are_listed_without_secrets()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var session = await server.SignInAsync(account.Id);
        await CreatePatAsync(server, session.AccessToken!, new("one"));
        await CreatePatAsync(server, session.AccessToken!, new("two"));

        var response = await server.SendAsync(HttpMethod.Get, "account/pats", session.AccessToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        JsonDocument.Parse(body).RootElement.GetArrayLength().ShouldBe(2);
        body.ShouldNotContain("pat_");
    }

    [Fact]
    public async Task Creating_a_pat_needs_step_up()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var session = await server.SignInAsync(account.Id, multiFactor: false);

        var response = await server.SendAsync(HttpMethod.Post, "account/pats", session.AccessToken, JsonContent.Create(new CreatePersonalAccessTokenRequest("ci")));

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await ProblemCodeAsync(response)).ShouldBe("step_up_required");
    }

    [Fact]
    public async Task A_pat_derived_token_cannot_create_another_pat()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var session = await server.SignInAsync(account.Id);
        var pat = await CreatePatAsync(server, session.AccessToken!, new("ci", AllowSensitiveActions: true));
        var derived = await server.ExchangePatAsync(pat.Secret);

        var response = await server.SendAsync(HttpMethod.Post, "account/pats", derived.AccessToken, JsonContent.Create(new CreatePersonalAccessTokenRequest("again")));

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await ProblemCodeAsync(response)).ShouldBe("pat_not_from_pat");
    }

    [Fact]
    public async Task An_out_of_range_lifetime_is_a_validation_problem()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var session = await server.SignInAsync(account.Id);

        var response = await server.SendAsync(HttpMethod.Post, "account/pats", session.AccessToken, JsonContent.Create(new CreatePersonalAccessTokenRequest("ci", 365)));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await ProblemCodeAsync(response)).ShouldBe("validation_failed");
    }
}

public sealed class DirectoryAndAdministrationTests
{
    [Fact]
    public async Task A_user_token_cannot_look_up_accounts()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var session = await server.SignInAsync(account.Id);

        (await server.SendAsync(HttpMethod.Get, $"directory/accounts/{account.Id}", session.AccessToken)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await server.SendAsync(HttpMethod.Get, "directory/accounts?email=ada@example.com", session.AccessToken)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_service_with_the_lookup_permission_can()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var service = await server.ClientCredentialsAsync();

        var byId = await server.SendAsync(HttpMethod.Get, $"directory/accounts/{account.Id}", service.AccessToken);
        var byEmail = await server.SendAsync(HttpMethod.Get, "directory/accounts?email=ADA@example.com", service.AccessToken);

        byId.StatusCode.ShouldBe(HttpStatusCode.OK);
        (await byEmail.Content.ReadFromJsonAsync<AccountContactDto>(TestContext.Current.CancellationToken))!.Id.ShouldBe(account.Id);
    }

    [Fact]
    public async Task A_service_without_the_lookup_permission_cannot()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var gateway = await server.ClientCredentialsAsync(TokenServerHost.GatewayClient, TokenServerHost.GatewaySecret);

        (await server.SendAsync(HttpMethod.Get, $"directory/accounts/{account.Id}", gateway.AccessToken)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Account_administration_needs_the_operator_permission()
    {
        await using var server = await TokenServerHost.StartAsync();
        var target = await server.CreateAccountAsync("target@example.com");
        var user = await server.CreateAccountAsync("user@example.com");
        var session = await server.SignInAsync(user.Id);

        (await server.SendAsync(HttpMethod.Post, $"admin/accounts/{target.Id}/disable", session.AccessToken)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }
}

public sealed class KeyRotationTests
{
    [Fact]
    public async Task A_new_key_is_published_at_once_and_signs_after_activation_without_a_restart()
    {
        await using var server = await TokenServerHost.StartAsync(new()
        {
            ["JeffOps:TokenServer:SigningKeys:RotationEnabled"] = "false", // driven by the test instead of the timer
            ["JeffOps:TokenServer:SigningKeys:RotationInterval"] = "1.00:00:00",
            ["JeffOps:TokenServer:SigningKeys:ActivationDelay"] = "02:00:00",
        });
        var account = await server.CreateAccountAsync();
        var firstKid = (await server.SignInAsync(account.Id)).Access.Kid;

        server.Time.Advance(TimeSpan.FromDays(1));
        await RotateAsync(server);

        (await KeyIdsAsync(server)).Count.ShouldBe(2, "the new key is published before it signs");
        (await server.SignInAsync(account.Id)).Access.Kid.ShouldBe(firstKid, "it doesn't sign before activation");

        server.Time.Advance(TimeSpan.FromHours(3));
        await RotateAsync(server);

        var secondKid = (await server.SignInAsync(account.Id)).Access.Kid;
        secondKid.ShouldNotBe(firstKid);
        (await KeyIdsAsync(server)).ShouldContain(firstKid, "the old key stays published during the overlap");
    }

    private static Task RotateAsync(TokenServerHost server) =>
        server.Services.GetServices<Microsoft.Extensions.Hosting.IHostedService>().OfType<KeyRotationService>().Single()
            .RotateOnceAsync(TestContext.Current.CancellationToken);

    private static async Task<List<string>> KeyIdsAsync(TokenServerHost server)
    {
        var json = await server.Client.GetStringAsync(new Uri(".well-known/jwks", UriKind.Relative), TestContext.Current.CancellationToken);
        using var document = JsonDocument.Parse(json);
        return [.. document.RootElement.GetProperty("keys").EnumerateArray().Select(key => key.GetProperty("kid").GetString()!)];
    }
}

public sealed class StartupTests
{
    [Fact]
    public async Task A_short_client_secret_fails_startup_outside_development()
    {
        var exception = await Should.ThrowAsync<InvalidOperationException>(() => TokenServerHost.StartAsync(new()
        {
            ["JeffOps:TokenServer:Clients:1:ClientSecret"] = "too-short",
        }));

        exception.Message.ShouldContain(TokenServerHost.ServiceClient);
    }

    [Fact]
    public async Task A_missing_issuer_fails_startup_outside_development() =>
        await Should.ThrowAsync<Microsoft.Extensions.Options.OptionsValidationException>(() => TokenServerHost.StartAsync(new()
        {
            ["JeffOps:TokenServer:Issuer"] = null,
        }));
}

public sealed class SessionRevocationTests
{
    [Fact]
    public async Task A_user_signs_out_everywhere_and_every_refresh_token_stops_working()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var first = await server.SignInAsync(account.Id);
        var second = await server.SignInAsync(account.Id);

        var revoked = await server.SendAsync(HttpMethod.Post, "account/sessions/revoke", first.AccessToken);

        revoked.StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await server.RefreshAsync(first.RefreshToken!)).Error.ShouldBe("invalid_grant");
        (await server.RefreshAsync(second.RefreshToken!)).Error.ShouldBe("invalid_grant");

        // A new sign-in afterwards works.
        server.Time.Advance(TimeSpan.FromSeconds(2));
        var fresh = await server.SignInAsync(account.Id);
        (await server.RefreshAsync(fresh.RefreshToken!)).Status.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task An_operator_can_end_someone_else_s_sessions()
    {
        await using var server = await TokenServerHost.StartAsync();
        var user = await server.CreateAccountAsync("user@example.com");
        var tokens = await server.SignInAsync(user.Id);
        var operatorAccount = await server.CreateAccountAsync("operator@example.com");
        var operatorTokens = await server.SignInAsync(operatorAccount.Id);

        // Without the administration permission, the route is forbidden.
        (await server.SendAsync(HttpMethod.Post, $"admin/accounts/{user.Id}/sessions/revoke", operatorTokens.AccessToken)).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await server.RefreshAsync(tokens.RefreshToken!)).Status.ShouldBe(HttpStatusCode.OK);

        // An operator (permission decided by the host) ends them.
        await using (var scope = server.Services.CreateAsyncScope())
        {
            var revoked = await scope.ServiceProvider.GetRequiredService<SharedKernel.Handlers.ICommandHandler<Application.Features.Accounts.RevokeSessionsCommand>>()
                .HandleAsync(new Application.Features.Accounts.RevokeSessionsCommand(operatorAccount.Id, user.Id), TestContext.Current.CancellationToken);
            revoked.IsSuccess.ShouldBeTrue();
        }

        (await server.RefreshAsync(tokens.RefreshToken!)).Error.ShouldBe("invalid_grant");
    }
}

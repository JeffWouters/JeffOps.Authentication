using System.Net;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;

namespace JeffOps.Authentication.Server.Tests;

public sealed class DiscoveryTests
{
    [Fact]
    public async Task The_discovery_document_advertises_the_endpoints_and_pkce()
    {
        await using var server = await TokenServerHost.StartAsync();

        var json = await server.Client.GetStringAsync(new Uri(".well-known/openid-configuration", UriKind.Relative), TestContext.Current.CancellationToken);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        root.GetProperty("issuer").GetString().ShouldBe("https://localhost/");
        root.GetProperty("authorization_endpoint").GetString().ShouldBe("https://localhost/connect/authorize");
        root.GetProperty("userinfo_endpoint").GetString().ShouldBe("https://localhost/connect/userinfo");
        root.GetProperty("end_session_endpoint").GetString().ShouldBe("https://localhost/connect/endsession");
        root.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(value => value.GetString()).ShouldContain("S256");
        root.GetProperty("grant_types_supported").EnumerateArray().Select(value => value.GetString())
            .ShouldBe(["authorization_code", "refresh_token", "client_credentials", "urn:jeffops:grant-type:pat"], ignoreOrder: true);
    }

    [Fact]
    public async Task Jwks_publishes_the_signing_key()
    {
        await using var server = await TokenServerHost.StartAsync();

        var json = await server.Client.GetStringAsync(new Uri(".well-known/jwks", UriKind.Relative), TestContext.Current.CancellationToken);
        using var document = JsonDocument.Parse(json);

        var key = document.RootElement.GetProperty("keys").EnumerateArray().ShouldHaveSingleItem();
        key.GetProperty("kty").GetString().ShouldBe("RSA");
        key.TryGetProperty("d", out _).ShouldBeFalse("only public parameters are published");
    }
}

public sealed class ClientCredentialsTests
{
    [Fact]
    public async Task A_service_gets_a_service_principal_token_with_its_permissions()
    {
        await using var server = await TokenServerHost.StartAsync();

        var response = await server.ClientCredentialsAsync();

        response.Status.ShouldBe(HttpStatusCode.OK, response.Body.ToString());
        response.RefreshToken.ShouldBeNull();
        response.Access.Subject.ShouldBe(TokenServerHost.ServiceClient);
        response.Claims("lvl").ShouldBe(["Service"]);
        response.Claims("perm").ShouldBe(["auth.accounts.lookup", "reports.*"], ignoreOrder: true);
        response.Access.Audiences.ShouldBe(["api"]);
    }

    [Fact]
    public async Task A_wrong_secret_is_refused()
    {
        await using var server = await TokenServerHost.StartAsync();

        var response = await server.ClientCredentialsAsync(secret: "wrong-secret-wrong-secret-wrong-secret");

        response.Status.ShouldNotBe(HttpStatusCode.OK);
        response.Error.ShouldBe("invalid_client");
    }

    [Fact]
    public async Task A_client_without_the_grant_is_refused()
    {
        await using var server = await TokenServerHost.StartAsync();

        var response = await server.ClientCredentialsAsync(TokenServerHost.BffClient, TokenServerHost.BffSecret);

        response.Error.ShouldBe("unauthorized_client");
    }
}

public sealed class AuthorizationCodeTests
{
    [Fact]
    public async Task Without_a_sign_in_the_user_is_sent_to_the_login_page_and_back()
    {
        await using var server = await TokenServerHost.StartAsync();

        var (location, _) = await server.AuthorizeAsync(accountId: null, extra: "&prompt=login");

        location.OriginalString.ShouldStartWith("/login?returnUrl=");
        var returnUrl = Uri.UnescapeDataString(location.OriginalString["/login?returnUrl=".Length..]);
        returnUrl.ShouldStartWith("/connect/authorize?");
        returnUrl.ShouldNotContain("prompt=login", customMessage: "otherwise the user would be asked to sign in forever");
    }

    [Fact]
    public async Task Prompt_none_without_a_sign_in_answers_login_required()
    {
        await using var server = await TokenServerHost.StartAsync();

        var (location, _) = await server.AuthorizeAsync(accountId: null, extra: "&prompt=none");

        TokenServerHost.QueryValue(location, "error").ShouldBe("login_required");
    }

    [Fact]
    public async Task The_code_flow_with_pkce_issues_access_identity_and_refresh_tokens()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var tenant = server.Tenants.AddMembership(account.Id);

        var tokens = await server.SignInAsync(account.Id);

        tokens.Status.ShouldBe(HttpStatusCode.OK, tokens.Body.ToString());
        tokens.RefreshToken.ShouldNotBeNull();
        tokens.IdToken.ShouldNotBeNull();
        tokens.Access.Subject.ShouldBe(account.Id.ToString());
        tokens.Claims("tid").ShouldBe([tenant.ToString()]);
        tokens.Claims("lvl").ShouldBe(["Tenant"]);
        tokens.Claims("amr").ShouldBe(["pwd", "mfa"], ignoreOrder: true);
        tokens.Claims("step_up").ShouldBe(["mfa"]);
        tokens.Access.Audiences.ShouldBe(["api"]);
    }

    [Fact]
    public async Task Without_multi_factor_there_is_no_step_up()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();

        var tokens = await server.SignInAsync(account.Id, multiFactor: false);

        tokens.Claims("step_up").ShouldBeEmpty();
        tokens.Claims("lvl").ShouldBe(["Tenant"]);
        tokens.Claims("tid").ShouldBeEmpty("an account without memberships gets a tenant-less session");
    }

    [Fact]
    public async Task Requiring_mfa_for_sign_in_refuses_a_single_factor_sign_in()
    {
        await using var server = await TokenServerHost.StartAsync(new() { ["JeffOps:TokenServer:Mfa:RequireForSignIn"] = "true" });
        var account = await server.CreateAccountAsync();

        var (location, _) = await server.AuthorizeAsync(account.Id, multiFactor: false);

        TokenServerHost.QueryValue(location, "error").ShouldBe("access_denied");
        TokenServerHost.QueryValue(location, "code").ShouldBe("mfa_required");
    }

    [Fact]
    public async Task A_disabled_account_cannot_sign_in()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        await server.WithAccountAsync(account.Id, existing => existing.Disable(server.Time.GetUtcNow()));

        var (location, _) = await server.AuthorizeAsync(account.Id);

        TokenServerHost.QueryValue(location, "error").ShouldBe("access_denied");
    }

    [Fact]
    public async Task The_tenant_hint_selects_the_tenant()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        server.Tenants.AddMembership(account.Id);
        var second = server.Tenants.AddMembership(account.Id, AccessLevel.Organization);

        var tokens = await server.SignInAsync(account.Id, tenantHint: second.ToString());

        tokens.Claims("tid").ShouldBe([second.ToString()]);
        tokens.Claims("lvl").ShouldBe(["Organization"]);
    }

    [Fact]
    public async Task Userinfo_returns_the_profile_for_the_granted_scopes()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync("grace@example.com");
        var tokens = await server.SignInAsync(account.Id);

        var response = await server.SendAsync(HttpMethod.Get, "connect/userinfo", tokens.AccessToken);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        body.RootElement.GetProperty("sub").GetString().ShouldBe(account.Id.ToString());
        body.RootElement.GetProperty("email").GetString().ShouldBe("grace@example.com");
        body.RootElement.GetProperty("name").GetString().ShouldBe("Ada Lovelace");
    }
}

public sealed class RefreshTests
{
    [Fact]
    public async Task Refreshing_rebuilds_claims_from_live_state()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var tenant = server.Tenants.AddMembership(account.Id);
        var tokens = await server.SignInAsync(account.Id);

        // The membership is upgraded after sign-in; the refreshed token reflects it.
        server.Tenants.Memberships[account.Id] = [new(tenant, null, null, AccessLevel.Organization)];
        var refreshed = await server.RefreshAsync(tokens.RefreshToken!);

        refreshed.Status.ShouldBe(HttpStatusCode.OK, refreshed.Body.ToString());
        refreshed.Claims("lvl").ShouldBe(["Organization"]);
        refreshed.RefreshToken.ShouldNotBe(tokens.RefreshToken, "refresh tokens rotate");
    }

    [Fact]
    public async Task A_disabled_account_can_no_longer_refresh()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var tokens = await server.SignInAsync(account.Id);
        await server.WithAccountAsync(account.Id, existing => existing.Disable(server.Time.GetUtcNow()));

        var refreshed = await server.RefreshAsync(tokens.RefreshToken!);

        refreshed.Error.ShouldBe("invalid_grant");
        refreshed.Code.ShouldBe("account_inactive");
    }

    [Fact]
    public async Task A_removed_membership_ends_the_session_in_that_tenant()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        server.Tenants.AddMembership(account.Id);
        var tokens = await server.SignInAsync(account.Id);
        server.Tenants.Memberships[account.Id] = [];

        var refreshed = await server.RefreshAsync(tokens.RefreshToken!);

        refreshed.Code.ShouldBe("no_membership");
    }

    [Fact]
    public async Task The_absolute_session_lifetime_is_not_extended_by_refreshing()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var tokens = await server.SignInAsync(account.Id);

        server.Time.Advance(TimeSpan.FromHours(8) + TimeSpan.FromMinutes(1));
        var refreshed = await server.RefreshAsync(tokens.RefreshToken!);

        // The refresh token's own lifetime is capped at the session's end, so the protocol layer already refuses it; the
        // session check behind it refuses the same (code session_expired) for any grant that outlives the session.
        refreshed.Error.ShouldBe("invalid_grant", refreshed.Body.ToString());
        refreshed.AccessToken.ShouldBeNull();
    }

    [Fact]
    public async Task A_directory_outage_is_a_server_error_not_a_sign_out()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        server.Tenants.AddMembership(account.Id);
        var tokens = await server.SignInAsync(account.Id);
        server.Tenants.Unavailable = true;

        var refreshed = await server.RefreshAsync(tokens.RefreshToken!);

        refreshed.Error.ShouldBe("server_error");
        refreshed.Code.ShouldBe("directory_unavailable");
    }

    [Fact]
    public async Task A_reused_refresh_token_is_refused()
    {
        await using var server = await TokenServerHost.StartAsync();
        var account = await server.CreateAccountAsync();
        var tokens = await server.SignInAsync(account.Id);

        (await server.RefreshAsync(tokens.RefreshToken!)).Status.ShouldBe(HttpStatusCode.OK);
        (await server.RefreshAsync(tokens.RefreshToken!)).Error.ShouldBe("invalid_grant");
    }
}

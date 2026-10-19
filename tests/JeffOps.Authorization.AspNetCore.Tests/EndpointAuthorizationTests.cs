using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authorization.AspNetCore.Evaluation;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace JeffOps.Authorization.AspNetCore.Tests;

public sealed class EndpointAuthorizationTests
{
    private static async Task<HttpResponseMessage> SendAsync(TestApp app, System.Security.Claims.ClaimsPrincipal user, HttpMethod method, string path)
    {
        using var request = TestApp.As(user, method, path);
        return await app.Client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static async Task<string?> ProblemCodeAsync(HttpResponseMessage response)
    {
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return body.RootElement.TryGetProperty("code", out var code) ? code.GetString() : null;
    }

    [Fact]
    public async Task Anonymous_callers_are_challenged()
    {
        await using var app = await TestApp.StartAsync();

        var response = await app.Client.GetAsync(new Uri("/findings", UriKind.Relative), TestContext.Current.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_role_grant_allows_and_its_absence_forbids()
    {
        await using var app = await TestApp.StartAsync();
        var reader = Guid.NewGuid();
        app.Data.Assign(reader, FakeDataSource.Reader);

        (await SendAsync(app, TestApp.User(reader), HttpMethod.Get, "/findings")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await SendAsync(app, TestApp.User(reader), HttpMethod.Post, "/findings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await SendAsync(app, TestApp.User(Guid.NewGuid()), HttpMethod.Get, "/findings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Root_is_allowed_without_assignments()
    {
        await using var app = await TestApp.StartAsync();

        var response = await SendAsync(app, TestApp.User(Guid.NewGuid(), ("lvl", "Root")), HttpMethod.Post, "/findings");

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_service_principal_is_authorized_by_its_permission_claims()
    {
        await using var app = await TestApp.StartAsync();
        var service = TestApp.Principal(("sub", "svc-reports"), ("lvl", "Service"), ("perm", "findings.*"));

        (await SendAsync(app, service, HttpMethod.Post, "/findings")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await SendAsync(app, service, HttpMethod.Post, "/policies")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_sensitive_permission_answers_step_up_required_with_rfc_9470_challenge()
    {
        await using var app = await TestApp.StartAsync();
        var admin = Guid.NewGuid();
        app.Data.Assign(admin, FakeDataSource.Admin);

        var refused = await SendAsync(app, TestApp.User(admin), HttpMethod.Post, "/policies");

        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        refused.Headers.WwwAuthenticate.ToString().ShouldContain("insufficient_user_authentication");
        refused.Content.Headers.ContentType?.MediaType.ShouldBe("application/problem+json");
        (await ProblemCodeAsync(refused)).ShouldBe("step_up_required");

        (await SendAsync(app, TestApp.User(admin, ("step_up", "mfa")), HttpMethod.Post, "/policies")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_route_exemption_lifts_step_up_on_that_route_only()
    {
        await using var app = await TestApp.StartAsync();
        var admin = Guid.NewGuid();
        app.Data.Assign(admin, FakeDataSource.Admin);

        (await SendAsync(app, TestApp.User(admin), HttpMethod.Post, "/policies/preview")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await SendAsync(app, TestApp.User(admin), HttpMethod.Post, "/policies")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Impersonation_cannot_write_refused_permissions_but_can_read_them()
    {
        await using var app = await TestApp.StartAsync();
        var target = Guid.NewGuid();
        app.Data.Assign(target, FakeDataSource.Admin);
        var impersonation = TestApp.User(target, ("act", "{\"sub\":\"support\"}"), ("step_up", "mfa"));

        var write = await SendAsync(app, impersonation, HttpMethod.Post, "/assignments");
        write.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await ProblemCodeAsync(write)).ShouldBe("impersonation_not_allowed");

        (await SendAsync(app, impersonation, HttpMethod.Get, "/assignments")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await SendAsync(app, impersonation, HttpMethod.Post, "/findings")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_route_refusing_impersonation_refuses_every_permission()
    {
        await using var app = await TestApp.StartAsync();
        var target = Guid.NewGuid();
        app.Data.Assign(target, FakeDataSource.Writer);

        (await SendAsync(app, TestApp.User(target, ("grant_id", "g-1")), HttpMethod.Post, "/lockbox")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await SendAsync(app, TestApp.User(target), HttpMethod.Post, "/lockbox")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_route_refusing_impersonation_refuses_it_without_a_permission_check()
    {
        await using var app = await TestApp.StartAsync(app =>
        {
            app.MapPost("/export", () => "ok").RequireAuthorization().RefuseUnderImpersonation();
            app.MapGet("/public", () => "ok").RefuseUnderImpersonation();
        });
        var user = Guid.NewGuid();

        var refused = await SendAsync(app, TestApp.User(user, ("grant_id", "g-1")), HttpMethod.Post, "/export");
        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await ProblemCodeAsync(refused)).ShouldBe("impersonation_not_allowed");
        (await SendAsync(app, TestApp.User(user, ("grant_id", "g-1")), HttpMethod.Get, "/public")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);

        (await SendAsync(app, TestApp.User(user), HttpMethod.Post, "/export")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await app.Client.GetAsync(new Uri("/public", UriKind.Relative), TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_route_requiring_step_up_requires_it_without_a_permission_check()
    {
        await using var app = await TestApp.StartAsync(app => app.MapPost("/keys/rotate", () => "ok").RequireAuthorization().RequireStepUp());
        var user = Guid.NewGuid();

        var refused = await SendAsync(app, TestApp.User(user), HttpMethod.Post, "/keys/rotate");
        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await ProblemCodeAsync(refused)).ShouldBe("step_up_required");

        (await SendAsync(app, TestApp.User(user, ("step_up", "mfa")), HttpMethod.Post, "/keys/rotate")).StatusCode.ShouldBe(HttpStatusCode.OK);
        var service = TestApp.Principal(("sub", "svc-keys"), ("lvl", "Service"));
        (await SendAsync(app, service, HttpMethod.Post, "/keys/rotate")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Renamed_impersonation_claims_still_mark_an_impersonation_token()
    {
        await using var app = await TestApp.StartAsync(services: services => services.AddSingleton(new ClaimNames { Actor = "actor", DelegationGrant = "delegation" }));
        var target = Guid.NewGuid();
        app.Data.Assign(target, FakeDataSource.Admin);

        var write = await SendAsync(app, TestApp.User(target, ("actor", "{\"sub\":\"support\"}")), HttpMethod.Post, "/assignments");
        write.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await ProblemCodeAsync(write)).ShouldBe("impersonation_not_allowed");
        (await SendAsync(app, TestApp.User(target, ("delegation", "g-1")), HttpMethod.Post, "/lockbox")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Permission_claims_count_only_on_service_tokens()
    {
        await using var app = await TestApp.StartAsync();

        (await SendAsync(app, TestApp.User(Guid.NewGuid(), ("perm", "findings.*")), HttpMethod.Post, "/findings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await SendAsync(app, TestApp.User(Guid.NewGuid(), ("lvl", "Delegated"), ("perm", "findings.*")), HttpMethod.Post, "/findings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task Root_needs_an_explicit_role_grant_for_break_glass()
    {
        await using var app = await TestApp.StartAsync(app =>
        {
            app.MapPost("/break-glass", () => "ok").RequireAuthorization("auth.impersonation.breakglass");
            app.MapPost("/findings", () => "ok").RequireAuthorization("findings.write");
        });
        var root = Guid.NewGuid();
        var granted = Guid.NewGuid();
        var breakGlass = Guid.NewGuid();
        app.Data.RolePermissions[breakGlass] = ["auth.impersonation.breakglass"];
        app.Data.Assign(granted, breakGlass);

        (await SendAsync(app, TestApp.User(root, ("lvl", "Root")), HttpMethod.Post, "/break-glass")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await SendAsync(app, TestApp.User(granted, ("lvl", "Root")), HttpMethod.Post, "/break-glass")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await SendAsync(app, TestApp.User(root, ("lvl", "Root")), HttpMethod.Post, "/findings")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task An_empty_impersonation_refusal_list_is_warned_about_at_startup()
    {
        var logs = new RecordingLoggerProvider();
        await using (await TestApp.StartAsync(
            settings: new Dictionary<string, string?>
            {
                ["JeffOps:Authorization:SensitivePermissions:0"] = "policy.write",
                ["JeffOps:Authorization:Cache:SealingKey"] = "test-sealing-key",
            },
            services: services => services.AddLogging(logging => logging.AddProvider(logs))))
        {
            logs.Messages.ShouldContain(message => message.Contains("ImpersonationRefusedPermissions", StringComparison.Ordinal));
        }

        var configured = new RecordingLoggerProvider();
        await using (await TestApp.StartAsync(services: services => services.AddLogging(logging => logging.AddProvider(configured))))
        {
            configured.Messages.ShouldNotContain(message => message.Contains("ImpersonationRefusedPermissions", StringComparison.Ordinal));
        }
    }

    [Fact]
    public async Task The_pat_ceiling_narrows_what_the_owner_may_do()
    {
        await using var app = await TestApp.StartAsync();
        var owner = Guid.NewGuid();
        app.Data.Assign(owner, FakeDataSource.Writer);
        var pat = TestApp.User(owner, ("pat_perm", "findings.read"));

        (await SendAsync(app, pat, HttpMethod.Get, "/findings")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await SendAsync(app, pat, HttpMethod.Post, "/findings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_read_only_delegation_narrows_a_delegated_session()
    {
        await using var app = await TestApp.StartAsync();
        var technician = Guid.NewGuid();
        app.Data.Assign(technician, FakeDataSource.Writer);
        var session = TestApp.User(technician, ("dlg_scope", "readonly"));

        (await SendAsync(app, session, HttpMethod.Get, "/findings")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await SendAsync(app, session, HttpMethod.Post, "/findings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_scope_aware_route_honours_instance_bound_assignments()
    {
        await using var app = await TestApp.StartAsync();
        var user = Guid.NewGuid();
        var workspace = Guid.NewGuid();
        app.Data.Assign(user, FakeDataSource.ItemReader, "workspace", workspace);

        (await SendAsync(app, TestApp.User(user), HttpMethod.Get, $"/workspaces/{workspace}/items")).StatusCode.ShouldBe(HttpStatusCode.OK);
        (await SendAsync(app, TestApp.User(user), HttpMethod.Get, $"/workspaces/{Guid.NewGuid()}/items")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await SendAsync(app, TestApp.User(user), HttpMethod.Get, "/workspaces/not-a-guid/items")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_tenant_wide_assignment_reaches_every_workspace()
    {
        await using var app = await TestApp.StartAsync();
        var user = Guid.NewGuid();
        app.Data.Assign(user, FakeDataSource.ItemReader, "tenant");

        (await SendAsync(app, TestApp.User(user), HttpMethod.Get, $"/workspaces/{Guid.NewGuid()}/items")).StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    [Fact]
    public async Task A_deny_policy_overrides_the_role_grant()
    {
        await using var app = await TestApp.StartAsync();
        var reader = Guid.NewGuid();
        app.Data.Assign(reader, FakeDataSource.Reader);
        app.Data.Policies.Add(new(Guid.NewGuid(), "no-after-hours", null, "findings.read", null,
            Domain.Policies.PolicyEffect.Deny, """{"ge":["environment.utcHour",0]}""", 0, true));

        (await SendAsync(app, TestApp.User(reader), HttpMethod.Get, "/findings")).StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task A_step_up_exemption_of_a_non_sensitive_permission_fails_startup()
    {
        var exception = await Should.ThrowAsync<InvalidOperationException>(() => TestApp.StartAsync(app =>
            app.MapPost("/oops", () => "ok").RequireAuthorization("findings.write").AllowWithoutStepUp("findings.write")));

        exception.Message.ShouldContain("findings.write");
    }
}

/// <summary>Keeps every warning logged, so a test can see what the host warned about.</summary>
internal sealed class RecordingLoggerProvider : ILoggerProvider
{
    public ConcurrentQueue<string> Messages { get; } = new();

    public ILogger CreateLogger(string categoryName) => new Logger(Messages);

    public void Dispose()
    {
    }

    private sealed class Logger(ConcurrentQueue<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (IsEnabled(logLevel))
            {
                messages.Enqueue(formatter(state, exception));
            }
        }
    }
}

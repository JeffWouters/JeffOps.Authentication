using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Enterprise.Endpoints;
using JeffOps.Authentication.Enterprise.Infrastructure;
using JeffOps.Authentication.Tests.Shared;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Server.Tests;

public sealed class ScimTests : IAsyncDisposable
{
    private static readonly Guid Contoso = Guid.NewGuid();

    private readonly string _database = TestDatabase.SqliteFile("scim");
    private readonly RecordingMemberships _memberships = new();
    private readonly ConcurrentQueue<IntegrationEvent> _events = new();
    private TokenServerHost _host = null!;
    private string _token = null!;

    [Fact]
    public async Task A_user_is_provisioned_found_by_filter_and_deprovisioned()
    {
        await StartAsync();

        var created = await ScimAsync(HttpMethod.Post, "Users", """
            {"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Jo@Contoso.com","externalId":"e-1",
             "name":{"givenName":"Jo","familyName":"Doe"},"emails":[{"value":"jo@contoso.com","primary":true}],"active":true}
            """);
        created.StatusCode.ShouldBe(HttpStatusCode.Created, await created.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        created.Content.Headers.ContentType!.MediaType.ShouldBe("application/scim+json");
        var user = await JsonAsync(created);
        var id = Guid.Parse(user.GetProperty("id").GetString()!);
        _memberships.Calls.ShouldContain(("add", Contoso, id));

        var found = await JsonAsync(await ScimAsync(HttpMethod.Get, "Users?filter=" + Uri.EscapeDataString("userName eq \"jo@contoso.com\"")));
        found.GetProperty("totalResults").GetInt32().ShouldBe(1);

        (await ScimAsync(HttpMethod.Post, "Users", """{"userName":"jo@contoso.com","emails":[{"value":"jo@contoso.com"}]}""")).StatusCode.ShouldBe(HttpStatusCode.Conflict);

        // Entra deactivates with a path-less replace and a string boolean.
        var patched = await ScimAsync(HttpMethod.Patch, $"Users/{id}", """
            {"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","value":{"active":"False"}}]}
            """);
        (await JsonAsync(patched)).GetProperty("active").GetBoolean().ShouldBeFalse();
        _memberships.Calls.ShouldContain(("remove", Contoso, id));
        (await AccountAsync(id)).CanAuthenticate.ShouldBeFalse();

        (await ScimAsync(HttpMethod.Delete, $"Users/{id}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await ScimAsync(HttpMethod.Get, $"Users/{id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task An_existing_verified_account_is_linked_not_disabled_on_deprovisioning()
    {
        await StartAsync();
        var existing = await _host.CreateAccountAsync("lee@contoso.com");

        var created = await JsonAsync(await ScimAsync(HttpMethod.Post, "Users", """{"userName":"lee@contoso.com","emails":[{"value":"lee@contoso.com"}]}"""));
        Guid.Parse(created.GetProperty("id").GetString()!).ShouldBe(existing.Id);

        (await ScimAsync(HttpMethod.Delete, $"Users/{existing.Id}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await AccountAsync(existing.Id)).CanAuthenticate.ShouldBeTrue();
        _memberships.Calls.ShouldContain(("remove", Contoso, existing.Id));
    }

    [Fact]
    public async Task Group_membership_changes_are_announced()
    {
        await StartAsync();
        var ann = await UserIdAsync("ann@contoso.com");
        var ben = await UserIdAsync("ben@contoso.com");

        var group = await JsonAsync(await ScimAsync(HttpMethod.Post, "Groups", $$"""{"displayName":"Engineers","members":[{"value":"{{ann}}"}]}"""));
        var groupId = Guid.Parse(group.GetProperty("id").GetString()!);
        Last<GroupMembershipChangedEvent>().Members.ShouldBe([ann]);
        var groupAtStart = await JsonAsync(await ScimAsync(HttpMethod.Get, $"Groups/{groupId}"));
        groupAtStart.GetProperty("members").GetArrayLength().ShouldBe(1, groupAtStart.ToString());

        await ScimAsync(HttpMethod.Patch, $"Groups/{groupId}", $$"""
            {"Operations":[{"op":"add","path":"members","value":[{"value":"{{ben}}"}]},{"op":"remove","path":"members[value eq \"{{ann}}\"]"}]}
            """);
        var changed = Last<GroupMembershipChangedEvent>();
        changed.Members.ShouldBe([ben]);
        changed.Added.ShouldBe([ben]);
        changed.Removed.ShouldBe([ann]);

        var groupNow = await JsonAsync(await ScimAsync(HttpMethod.Get, $"Groups/{groupId}"));
        groupNow.GetProperty("members").GetArrayLength().ShouldBe(1, groupNow.ToString());
        var benNow = await JsonAsync(await ScimAsync(HttpMethod.Get, $"Users/{ben}"));
        benNow.GetProperty("groups").GetArrayLength().ShouldBe(1, benNow.ToString());
        benNow.GetProperty("groups")[0].GetProperty("display").GetString().ShouldBe("Engineers");
        (await ScimAsync(HttpMethod.Post, "Groups", $$"""{"displayName":"Ghosts","members":[{"value":"{{Guid.NewGuid()}}"}]}""")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        (await ScimAsync(HttpMethod.Delete, $"Groups/{groupId}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        Last<GroupDeletedEvent>().FormerMembers.ShouldBe([ben]);
    }

    [Fact]
    public async Task Only_addresses_in_the_tenant_s_verified_domains_can_be_provisioned()
    {
        await StartAsync();
        var outsider = await _host.CreateAccountAsync("victim@fabrikam.com");

        // Linking someone else's account, or squatting on an address the tenant doesn't own, is refused.
        (await ScimAsync(HttpMethod.Post, "Users", """{"userName":"victim@fabrikam.com","emails":[{"value":"victim@fabrikam.com"}]}""")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await ScimAsync(HttpMethod.Post, "Users", """{"userName":"nobody@unclaimed.test"}""")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await ScimAsync(HttpMethod.Get, $"Users/{outsider.Id}")).StatusCode.ShouldBe(HttpStatusCode.NotFound);
        _memberships.Calls.ShouldNotContain(call => call.AccountId == outsider.Id);

        // Nor can a provisioned user's address be changed to one outside them.
        var jo = await UserIdAsync("jo@contoso.com");
        (await ScimAsync(HttpMethod.Patch, $"Users/{jo}", """
            {"Operations":[{"op":"replace","path":"emails[type eq \"work\"].value","value":"victim@fabrikam.com"}]}
            """)).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await AccountAsync(jo)).Email.ShouldBe("jo@contoso.com");
    }

    [Fact]
    public async Task When_the_tenant_system_is_down_nothing_changes_and_a_retry_completes()
    {
        await StartAsync();
        var jo = await UserIdAsync("jo@contoso.com");

        _memberships.Down = true;
        (await ScimAsync(HttpMethod.Delete, $"Users/{jo}")).StatusCode.ShouldBe(HttpStatusCode.ServiceUnavailable);
        (await ScimAsync(HttpMethod.Get, $"Users/{jo}")).StatusCode.ShouldBe(HttpStatusCode.OK, "the identity provider's retry must still find the user");
        (await ScimAsync(HttpMethod.Post, "Users", """{"userName":"kim@contoso.com"}""")).StatusCode.ShouldBe(HttpStatusCode.ServiceUnavailable);
        (await JsonAsync(await ScimAsync(HttpMethod.Get, "Users?filter=" + Uri.EscapeDataString("userName eq \"kim@contoso.com\"")))).GetProperty("totalResults").GetInt32().ShouldBe(0);

        _memberships.Down = false;
        (await ScimAsync(HttpMethod.Delete, $"Users/{jo}")).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        _memberships.Calls.ShouldContain(("remove", Contoso, jo));
        (await ScimAsync(HttpMethod.Post, "Users", """{"userName":"kim@contoso.com"}""")).StatusCode.ShouldBe(HttpStatusCode.Created);
    }

    [Fact]
    public async Task A_deactivated_user_drops_out_of_announced_group_members_until_reactivated()
    {
        await StartAsync();
        var ann = await UserIdAsync("ann@contoso.com");
        var ben = await UserIdAsync("ben@contoso.com");
        await JsonAsync(await ScimAsync(HttpMethod.Post, "Groups", $$"""{"displayName":"Admins","members":[{"value":"{{ann}}"},{"value":"{{ben}}"}]}"""));
        var created = Last<GroupMembershipChangedEvent>();

        await JsonAsync(await ScimAsync(HttpMethod.Patch, $"Users/{ann}", """{"Operations":[{"op":"replace","value":{"active":false}}]}"""));
        var deactivated = Last<GroupMembershipChangedEvent>();
        deactivated.Members.ShouldBe([ben]);
        deactivated.Removed.ShouldBe([ann]);
        deactivated.Version.ShouldBeGreaterThan(created.Version);

        await JsonAsync(await ScimAsync(HttpMethod.Patch, $"Users/{ann}", """{"Operations":[{"op":"replace","value":{"active":true}}]}"""));
        var reactivated = Last<GroupMembershipChangedEvent>();
        reactivated.Members.ShouldBe([ann, ben], ignoreOrder: true);
        reactivated.Added.ShouldBe([ann]);
        reactivated.Version.ShouldBeGreaterThan(deactivated.Version);
    }

    [Fact]
    public async Task Provisioning_does_not_undo_an_operator_s_disable()
    {
        await StartAsync();
        var jo = await UserIdAsync("jo@contoso.com");
        await _host.WithAccountAsync(jo, account => account.Disable(_host.Time.GetUtcNow()));

        await JsonAsync(await ScimAsync(HttpMethod.Patch, $"Users/{jo}", """{"Operations":[{"op":"replace","value":{"active":false}}]}"""));
        await JsonAsync(await ScimAsync(HttpMethod.Patch, $"Users/{jo}", """{"Operations":[{"op":"replace","value":{"active":true}}]}"""));

        (await AccountAsync(jo)).CanAuthenticate.ShouldBeFalse();
    }

    [Fact]
    public async Task Hostile_filters_and_bodies_get_scim_errors_never_server_errors()
    {
        await StartAsync();
        var jo = await UserIdAsync("jo@contoso.com");
        var group = Guid.Parse((await JsonAsync(await ScimAsync(HttpMethod.Post, "Groups", $$"""{"displayName":"Fuzz","members":[{"value":"{{jo}}"}]}"""))).GetProperty("id").GetString()!);
        var random = new Random(7644);

        for (var round = 0; round < 250; round++)
        {
            var filter = RandomFilter(random);
            await ShouldNotFailAsync(HttpMethod.Get, (random.Next(2) == 0 ? "Users" : "Groups") + "?filter=" + Uri.EscapeDataString(filter)
                + $"&startIndex={random.Next(-5, 5)}&count={random.Next(-5, 500)}", null, filter);

            var patch = RandomPatch(random, jo);
            await ShouldNotFailAsync(HttpMethod.Patch, random.Next(2) == 0 ? $"Users/{jo}" : $"Groups/{group}", patch, patch);

            var body = JsonSerializer.Serialize(RandomJson(random, 3, jo));
            await ShouldNotFailAsync(random.Next(2) == 0 ? HttpMethod.Post : HttpMethod.Put, random.Next(2) == 0 ? "Users" + (random.Next(2) == 0 ? $"/{jo}" : "") : "Groups" + (random.Next(2) == 0 ? $"/{group}" : ""), body, body);

            // Bulk: neither the request nor any operation in it fails with a server error.
            string[] methods = ["POST", "PUT", "PATCH", "DELETE", "GET", "post", ""];
            string[] paths = ["/Users", $"/Users/{jo}", "/Groups", $"/Groups/{group}", $"/Groups/bulkId:b{round - 1}", "/Users/bulkId:", "/Bulk", "Users/x/y", ""];
            var bulk = JsonSerializer.Serialize(new
            {
                schemas = new[] { "urn:ietf:params:scim:api:messages:2.0:BulkRequest" },
                failOnErrors = random.Next(-1, 3),
                Operations = new[]
                {
                    new Dictionary<string, object?> { ["method"] = methods[random.Next(methods.Length)], ["path"] = paths[random.Next(paths.Length)], ["bulkId"] = $"b{round}", ["data"] = RandomJson(random, 3, jo) },
                    new Dictionary<string, object?> { ["method"] = methods[random.Next(methods.Length)], ["path"] = paths[random.Next(paths.Length)], ["version"] = RandomJson(random, 0, jo), ["data"] = RandomPatch(random, jo) },
                },
            });
            var bulkResponse = await ScimAsync(HttpMethod.Post, "Bulk", bulk);
            ((int)bulkResponse.StatusCode).ShouldBeLessThan(500, bulk);
            if (bulkResponse.StatusCode == HttpStatusCode.OK)
            {
                foreach (var operation in (await JsonAsync(bulkResponse)).GetProperty("Operations").EnumerateArray())
                {
                    int.Parse(operation.GetProperty("status").GetString()!, System.Globalization.CultureInfo.InvariantCulture).ShouldBeLessThan(500, bulk);
                }
            }
        }

        // The user and group are still readable afterwards: nothing corrupted them.
        (await ScimAsync(HttpMethod.Get, $"Groups/{group}")).StatusCode.ShouldBeOneOf(HttpStatusCode.OK, HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Long_names_are_refused_or_cut_to_what_the_store_keeps()
    {
        await StartAsync();
        var longGiven = new string('a', 201);
        (await ScimAsync(HttpMethod.Post, "Users", $$"""{"userName":"long@contoso.com","name":{"givenName":"{{longGiven}}"},"emails":[{"value":"long@contoso.com"}]}"""))
            .StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        // A display name SCIM allows, longer than an account's: the account keeps the first 200 characters (not half a pair).
        var display = string.Concat(Enumerable.Repeat("\U0001F600", 128));
        var created = await JsonAsync(await ScimAsync(HttpMethod.Post, "Users", $$"""{"userName":"wide@contoso.com","displayName":"{{display}}","emails":[{"value":"wide@contoso.com"}]}"""));
        var account = await AccountAsync(Guid.Parse(created.GetProperty("id").GetString()!));
        account.DisplayName.Length.ShouldBe(200);
        char.IsHighSurrogate(account.DisplayName[^1]).ShouldBeFalse();
    }

    [Fact]
    public async Task ETags_guard_changes_and_answer_conditional_reads()
    {
        await StartAsync();
        var created = await ScimAsync(HttpMethod.Post, "Users", """{"userName":"jo@contoso.com","emails":[{"value":"jo@contoso.com"}]}""");
        var id = (await JsonAsync(created)).GetProperty("id").GetString();
        var etag = created.Headers.ETag.ShouldNotBeNull().ToString();
        etag.ShouldStartWith("W/\"");

        (await ScimAsync(HttpMethod.Get, $"Users/{id}", ifNoneMatch: etag)).StatusCode.ShouldBe(HttpStatusCode.NotModified);
        (await ScimAsync(HttpMethod.Get, $"Users/{id}", ifNoneMatch: "W/\"999\"")).StatusCode.ShouldBe(HttpStatusCode.OK);

        // A change made against an old version is refused, and changes nothing.
        var stale = await ScimAsync(HttpMethod.Put, $"Users/{id}", """{"userName":"jo@contoso.com","displayName":"Stale","emails":[{"value":"jo@contoso.com"}]}""", ifMatch: "W/\"999\"");
        stale.StatusCode.ShouldBe(HttpStatusCode.PreconditionFailed);
        var unchanged = await JsonAsync(await ScimAsync(HttpMethod.Get, $"Users/{id}"));
        (unchanged.TryGetProperty("displayName", out var name) && name.ValueKind == JsonValueKind.String ? name.GetString() : null).ShouldNotBe("Stale");

        var patched = await ScimAsync(HttpMethod.Patch, $"Users/{id}", """{"Operations":[{"op":"replace","path":"displayName","value":"Jo"}]}""", ifMatch: etag);
        patched.StatusCode.ShouldBe(HttpStatusCode.OK);
        var next = patched.Headers.ETag.ShouldNotBeNull().ToString();
        next.ShouldNotBe(etag);
        (await JsonAsync(patched)).GetProperty("meta").GetProperty("version").GetString().ShouldBe(next);

        (await ScimAsync(HttpMethod.Delete, $"Users/{id}", ifMatch: etag)).StatusCode.ShouldBe(HttpStatusCode.PreconditionFailed);
        (await ScimAsync(HttpMethod.Delete, $"Users/{id}", ifMatch: "*")).StatusCode.ShouldBe(HttpStatusCode.NoContent);

        var group = await ScimAsync(HttpMethod.Post, "Groups", """{"displayName":"Engineers"}""");
        var groupId = (await JsonAsync(group)).GetProperty("id").GetString();
        (await ScimAsync(HttpMethod.Patch, $"Groups/{groupId}", """{"Operations":[{"op":"replace","path":"displayName","value":"Eng"}]}""", ifMatch: "W/\"999\""))
            .StatusCode.ShouldBe(HttpStatusCode.PreconditionFailed);
        (await ScimAsync(HttpMethod.Patch, $"Groups/{groupId}", """{"Operations":[{"op":"replace","path":"displayName","value":"Eng"}]}""", ifMatch: group.Headers.ETag!.ToString()))
            .StatusCode.ShouldBe(HttpStatusCode.OK);

        var config = await JsonAsync(await ScimAsync(HttpMethod.Get, "ServiceProviderConfig"));
        config.GetProperty("etag").GetProperty("supported").GetBoolean().ShouldBeTrue();
        config.GetProperty("bulk").GetProperty("supported").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task Bulk_creates_users_and_a_group_that_refers_to_them()
    {
        await StartAsync();

        var response = await ScimAsync(HttpMethod.Post, "Bulk", """
            {"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[
              {"method":"POST","path":"/Users","bulkId":"ada","data":{"userName":"ada@contoso.com","emails":[{"value":"ada@contoso.com"}]}},
              {"method":"POST","path":"/Users","bulkId":"bob","data":{"userName":"bob@contoso.com","emails":[{"value":"bob@contoso.com"}]}},
              {"method":"POST","path":"/Groups","bulkId":"eng","data":{"displayName":"Engineers","members":[{"value":"bulkId:ada"},{"value":"bulkId:bob"}]}},
              {"method":"PATCH","path":"/Groups/bulkId:eng","data":{"Operations":[{"op":"remove","path":"members","value":[{"value":"bulkId:bob"}]}]}}
            ]}
            """);

        var body = await JsonAsync(response);
        body.GetProperty("schemas")[0].GetString().ShouldBe("urn:ietf:params:scim:api:messages:2.0:BulkResponse");
        var results = body.GetProperty("Operations").EnumerateArray().ToList();
        results.Select(result => result.GetProperty("status").GetString()).ShouldBe(["201", "201", "201", "200"]);
        results.ShouldAllBe(result => result.GetProperty("location").GetString()!.Contains("/scim/v2/"));
        results.ShouldAllBe(result => result.GetProperty("version").GetString()!.StartsWith("W/"));

        var ada = results[0].GetProperty("location").GetString()!.Split('/')[^1];
        var groupId = results[2].GetProperty("location").GetString()!.Split('/')[^1];
        var group = await JsonAsync(await ScimAsync(HttpMethod.Get, $"Groups/{groupId}"));
        group.GetProperty("members").EnumerateArray().Select(member => member.GetProperty("value").GetString()).ShouldBe([ada]);
    }

    [Fact]
    public async Task Bulk_reports_each_failure_and_stops_after_fail_on_errors()
    {
        await StartAsync();
        await UserIdAsync("taken@contoso.com");

        var response = await ScimAsync(HttpMethod.Post, "Bulk", """
            {"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"failOnErrors":2,"Operations":[
              {"method":"POST","path":"/Users","bulkId":"a","data":{"displayName":"no userName"}},
              {"method":"POST","path":"/Groups","bulkId":"g","data":{"displayName":"Ghosts","members":[{"value":"bulkId:nobody"}]}},
              {"method":"POST","path":"/Users","bulkId":"c","data":{"userName":"late@contoso.com","emails":[{"value":"late@contoso.com"}]}}
            ]}
            """);

        var results = (await JsonAsync(response)).GetProperty("Operations").EnumerateArray().ToList();
        results.Select(result => result.GetProperty("status").GetString()).ShouldBe(["400", "409"]);
        results.ShouldAllBe(result => result.GetProperty("response").GetProperty("detail").GetString()!.Length > 0);
        (await JsonAsync(await ScimAsync(HttpMethod.Get, "Users?filter=" + Uri.EscapeDataString("userName eq \"late@contoso.com\"")))).GetProperty("totalResults").GetInt32()
            .ShouldBe(0, "operations after the error limit don't run");

        // Without a limit every operation runs; a duplicate is reported, the rest still succeed.
        var all = await ScimAsync(HttpMethod.Post, "Bulk", """
            {"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[
              {"method":"POST","path":"/Users","bulkId":"t","data":{"userName":"taken@contoso.com","emails":[{"value":"taken@contoso.com"}]}},
              {"method":"POST","path":"/Users","bulkId":"n","data":{"userName":"new@contoso.com","emails":[{"value":"new@contoso.com"}]}},
              {"method":"DELETE","path":"/Users/not-an-id"}
            ]}
            """);
        (await JsonAsync(all)).GetProperty("Operations").EnumerateArray().Select(result => result.GetProperty("status").GetString()).ShouldBe(["409", "201", "404"]);

        (await ScimAsync(HttpMethod.Post, "Bulk", """{"Operations":[]}""")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        var tooMany = string.Join(',', Enumerable.Range(0, ScimEndpoints.MaxBulkOperations + 1).Select(_ => $$"""{"method":"DELETE","path":"/Users/{{Guid.NewGuid()}}"}"""));
        (await ScimAsync(HttpMethod.Post, "Bulk", $$"""{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[{{tooMany}}]}"""))
            .StatusCode.ShouldBe(HttpStatusCode.RequestEntityTooLarge);
    }

    [Fact]
    public async Task Bulk_resolves_references_to_operations_later_in_the_request()
    {
        await StartAsync();

        var response = await ScimAsync(HttpMethod.Post, "Bulk", """
            {"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[
              {"method":"POST","path":"/Groups","bulkId":"eng","data":{"displayName":"Engineers","members":[{"value":"bulkId:ada"}]}},
              {"method":"PATCH","path":"/Users/bulkId:ada","data":{"Operations":[{"op":"replace","path":"displayName","value":"Ada L."}]}},
              {"method":"POST","path":"/Users","bulkId":"ada","data":{"userName":"ada@contoso.com","emails":[{"value":"ada@contoso.com"}]}}
            ]}
            """);

        var results = (await JsonAsync(response)).GetProperty("Operations").EnumerateArray().ToList();
        results.Select(result => result.TryGetProperty("bulkId", out var id) ? id.GetString() : result.GetProperty("method").GetString())
            .ShouldBe(["eng", "PATCH", "ada"], "answers come in the order the client sent the operations");
        results.Select(result => result.GetProperty("status").GetString()).ShouldBe(["201", "200", "201"]);
        var ada = results[2].GetProperty("location").GetString()!.Split('/')[^1];
        var group = await JsonAsync(await ScimAsync(HttpMethod.Get, $"Groups/{results[0].GetProperty("location").GetString()!.Split('/')[^1]}"));
        group.GetProperty("members").EnumerateArray().Select(member => member.GetProperty("value").GetString()).ShouldBe([ada]);
        (await JsonAsync(await ScimAsync(HttpMethod.Get, $"Users/{ada}"))).GetProperty("displayName").GetString().ShouldBe("Ada L.");

        // References that can never resolve are reported, and nothing of them is created.
        var circular = await ScimAsync(HttpMethod.Post, "Bulk", """
            {"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[
              {"method":"POST","path":"/Users","bulkId":"x","data":{"userName":"x@contoso.com","externalId":"bulkId:y","emails":[{"value":"x@contoso.com"}]}},
              {"method":"POST","path":"/Users","bulkId":"y","data":{"userName":"y@contoso.com","externalId":"bulkId:x","emails":[{"value":"y@contoso.com"}]}},
              {"method":"POST","path":"/Groups","bulkId":"self","data":{"displayName":"Self","externalId":"bulkId:self"}}
            ]}
            """);
        (await JsonAsync(circular)).GetProperty("Operations").EnumerateArray().Select(result => result.GetProperty("status").GetString()).ShouldBe(["409", "409", "409"]);
        (await JsonAsync(await ScimAsync(HttpMethod.Get, "Users?filter=" + Uri.EscapeDataString("userName eq \"x@contoso.com\"")))).GetProperty("totalResults").GetInt32().ShouldBe(0);
    }

    [Fact]
    public async Task Lists_sort_by_the_attribute_asked_for()
    {
        await StartAsync();
        foreach (var (user, display) in new[] { ("bea@contoso.com", "Bea"), ("Abe@contoso.com", (string?)null), ("cy@contoso.com", "al") })
        {
            var body = display is null
                ? $$"""{"userName":"{{user}}","emails":[{"value":"{{user.ToLowerInvariant()}}"}]}"""
                : $$"""{"userName":"{{user}}","displayName":"{{display}}","emails":[{"value":"{{user.ToLowerInvariant()}}"}]}""";
            (await ScimAsync(HttpMethod.Post, "Users", body)).StatusCode.ShouldBe(HttpStatusCode.Created);
            _host.Time.Advance(TimeSpan.FromSeconds(1));
        }

        async Task<string?[]> UsersAsync(string query) =>
            [.. (await JsonAsync(await ScimAsync(HttpMethod.Get, "Users?" + query))).GetProperty("Resources").EnumerateArray().Select(user => user.GetProperty("userName").GetString())];

        (await UsersAsync("sortBy=userName")).ShouldBe(["Abe@contoso.com", "bea@contoso.com", "cy@contoso.com"], "case doesn't decide the order");
        (await UsersAsync("sortBy=userName&sortOrder=descending")).ShouldBe(["cy@contoso.com", "bea@contoso.com", "Abe@contoso.com"]);
        (await UsersAsync("sortBy=displayName")).ShouldBe(["cy@contoso.com", "bea@contoso.com", "Abe@contoso.com"], "no value comes last");
        (await UsersAsync("sortBy=displayName&sortOrder=descending")).ShouldBe(["Abe@contoso.com", "bea@contoso.com", "cy@contoso.com"]);
        (await UsersAsync("sortBy=urn:ietf:params:scim:schemas:core:2.0:User:userName&count=2&startIndex=2")).ShouldBe(["bea@contoso.com", "cy@contoso.com"]);

        (await UsersAsync("sortBy=meta.created&sortOrder=descending")).ShouldBe(["cy@contoso.com", "Abe@contoso.com", "bea@contoso.com"], "newest first");
        (await ScimAsync(HttpMethod.Get, "Users?sortBy=password")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await ScimAsync(HttpMethod.Get, "Users?sortBy=userName&sortOrder=sideways")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);

        foreach (var name in new[] { "Beta", "alpha", "Gamma" })
        {
            await ScimAsync(HttpMethod.Post, "Groups", $$"""{"displayName":"{{name}}"}""");
        }

        var groups = await JsonAsync(await ScimAsync(HttpMethod.Get, "Groups?sortBy=displayName&sortOrder=descending"));
        groups.GetProperty("Resources").EnumerateArray().Select(group => group.GetProperty("displayName").GetString()).ShouldBe(["Gamma", "Beta", "alpha"]);
        (await JsonAsync(await ScimAsync(HttpMethod.Get, "ServiceProviderConfig"))).GetProperty("sort").GetProperty("supported").GetBoolean().ShouldBeTrue();
    }

    [Fact]
    public async Task Attributes_select_what_a_resource_returns()
    {
        await StartAsync();
        var created = await JsonAsync(await ScimAsync(HttpMethod.Post, "Users?attributes=userName", """
            {"userName":"jo@contoso.com","name":{"givenName":"Jo","familyName":"Doe"},"emails":[{"value":"jo@contoso.com","primary":true}]}
            """));
        created.EnumerateObject().Select(property => property.Name).ShouldBe(["schemas", "id", "userName"], ignoreOrder: true);
        var id = created.GetProperty("id").GetString();

        var some = await JsonAsync(await ScimAsync(HttpMethod.Get, $"Users/{id}?attributes=urn:ietf:params:scim:schemas:core:2.0:User:name.givenName,emails.value"));
        some.EnumerateObject().Select(property => property.Name).ShouldBe(["schemas", "id", "name", "emails"], ignoreOrder: true);
        some.GetProperty("name").EnumerateObject().Select(property => property.Name).ShouldBe(["givenName"]);
        some.GetProperty("emails")[0].EnumerateObject().Select(property => property.Name).ShouldBe(["value"]);

        var without = await JsonAsync(await ScimAsync(HttpMethod.Get, $"Users/{id}?excludedAttributes=emails,meta,name.familyName,id"));
        without.TryGetProperty("emails", out _).ShouldBeFalse();
        without.TryGetProperty("meta", out _).ShouldBeFalse();
        without.GetProperty("id").GetString().ShouldBe(id, "id is always returned");
        without.GetProperty("name").TryGetProperty("familyName", out _).ShouldBeFalse();
        without.GetProperty("name").GetProperty("givenName").GetString().ShouldBe("Jo");

        await ScimAsync(HttpMethod.Post, "Groups", $$"""{"displayName":"Engineers","members":[{"value":"{{id}}"}]}""");
        var groups = await JsonAsync(await ScimAsync(HttpMethod.Get, "Groups?excludedAttributes=members"));
        groups.GetProperty("Resources")[0].TryGetProperty("members", out _).ShouldBeFalse();
        groups.GetProperty("Resources")[0].GetProperty("displayName").GetString().ShouldBe("Engineers");

        var patched = await JsonAsync(await ScimAsync(HttpMethod.Patch, $"Users/{id}?attributes=displayName", """{"Operations":[{"op":"replace","path":"displayName","value":"Jo D."}]}"""));
        patched.EnumerateObject().Select(property => property.Name).ShouldBe(["schemas", "id", "displayName"], ignoreOrder: true);
    }

    [Fact]
    public async Task Filters_follow_the_scim_grammar()
    {
        await StartAsync();
        var ada = await CreateUserAsync("""{"userName":"ada@contoso.com","externalId":"E-1","displayName":"Ada Lovelace","name":{"givenName":"Ada"},"emails":[{"value":"ada@contoso.com"}]}""");
        _host.Time.Advance(TimeSpan.FromMinutes(1));
        var since = _host.Time.GetUtcNow().ToString("O", System.Globalization.CultureInfo.InvariantCulture);
        _host.Time.Advance(TimeSpan.FromMinutes(1));
        var bob = await CreateUserAsync("""{"userName":"bob@contoso.com","externalId":"e-2","displayName":"Bob","active":false,"emails":[{"value":"bob@contoso.com"}]}""");
        var cy = await CreateUserAsync("""{"userName":"cy@contoso.com","emails":[{"value":"cy@contoso.com"}]}""");

        async Task<string?[]> UsersAsync(string filter)
        {
            var response = await ScimAsync(HttpMethod.Get, "Users?sortBy=userName&filter=" + Uri.EscapeDataString(filter));
            return [.. (await JsonAsync(response)).GetProperty("Resources").EnumerateArray().Select(user => user.GetProperty("id").GetString())];
        }

        (await UsersAsync("""userName sw "A" """)).ShouldBe([ada]);
        (await UsersAsync("""displayName co "LOVE" """)).ShouldBe([ada], "strings compare case-insensitively");
        (await UsersAsync("""externalId eq "e-1" """)).ShouldBeEmpty("externalId is case-exact");
        (await UsersAsync("""externalId eq "E-1" """)).ShouldBe([ada]);
        (await UsersAsync("""not (displayName pr)""")).ShouldBe([cy]);
        (await UsersAsync("""active eq false""")).ShouldBe([bob]);
        (await UsersAsync("""userName ne "ada@contoso.com" """)).ShouldBe([bob, cy]);
        (await UsersAsync("""(userName eq "ada@contoso.com" or userName eq "bob@contoso.com") and active eq true""")).ShouldBe([ada]);
        (await UsersAsync($$"""meta.created gt "{{since}}" """)).ShouldBe([bob, cy]);
        (await UsersAsync("""urn:ietf:params:scim:schemas:core:2.0:User:name.givenName eq "ada" """)).ShouldBe([ada]);
        (await UsersAsync($$"""id eq "{{bob}}" """)).ShouldBe([bob]);
        (await UsersAsync("""displayName gt "B" and displayName lt "C" """)).ShouldBe([bob]);
        (await UsersAsync("""displayName ew "e" """)).ShouldBe([ada], "JSON escapes in strings");

        var engineers = (await JsonAsync(await ScimAsync(HttpMethod.Post, "Groups", $$"""{"displayName":"Engineers","members":[{"value":"{{ada}}"}]}"""))).GetProperty("id").GetString();
        await ScimAsync(HttpMethod.Post, "Groups", """{"displayName":"Empty"}""");
        async Task<string?[]> GroupsAsync(string filter) =>
            [.. (await JsonAsync(await ScimAsync(HttpMethod.Get, "Groups?filter=" + Uri.EscapeDataString(filter)))).GetProperty("Resources").EnumerateArray().Select(group => group.GetProperty("id").GetString())];
        (await GroupsAsync($$"""members[value eq "{{ada}}"]""")).ShouldBe([engineers]);
        (await GroupsAsync($$"""members.value eq "{{ada}}" """)).ShouldBe([engineers]);
        (await GroupsAsync("""members pr""")).ShouldBe([engineers]);
        (await GroupsAsync($$"""members[value eq "{{bob}}"] or displayName sw "eng" """)).ShouldBe([engineers]);

        foreach (var invalid in new[]
        {
            "userName eq", "userName xx \"a\"", "emails eq \"a\"", "active eq \"yes\"", "meta.created gt \"yesterday\"",
            "userName eq \"unclosed", "not userName pr", "(userName pr", "userName eq a", new string('(', 40) + "userName pr" + new string(')', 40),
            string.Join(" or ", Enumerable.Repeat("userName pr", 101)),
        })
        {
            var response = await ScimAsync(HttpMethod.Get, "Users?filter=" + Uri.EscapeDataString(invalid));
            response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, invalid);
            (await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).ShouldContain("invalidFilter", customMessage: invalid);
        }
    }

    [Fact]
    public async Task Searches_take_the_list_parameters_in_a_body()
    {
        await StartAsync();
        await CreateUserAsync("""{"userName":"ada@contoso.com","displayName":"Ada","emails":[{"value":"ada@contoso.com"}]}""");
        await CreateUserAsync("""{"userName":"bob@contoso.com","displayName":"Bob","emails":[{"value":"bob@contoso.com"}]}""");
        await ScimAsync(HttpMethod.Post, "Groups", """{"displayName":"Admins"}""");
        await ScimAsync(HttpMethod.Post, "Groups", """{"displayName":"Builders"}""");

        var users = await JsonAsync(await ScimAsync(HttpMethod.Post, "Users/.search", """
            {"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"filter":"userName sw \"a\"","attributes":["userName"],"sortBy":"userName","startIndex":1,"count":10}
            """));
        users.GetProperty("totalResults").GetInt32().ShouldBe(1);
        users.GetProperty("Resources")[0].EnumerateObject().Select(property => property.Name).ShouldBe(["schemas", "id", "userName"], ignoreOrder: true);

        var groups = await JsonAsync(await ScimAsync(HttpMethod.Post, "Groups/.search", """
            {"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"sortBy":"displayName","sortOrder":"descending","excludedAttributes":"members"}
            """));
        groups.GetProperty("Resources").EnumerateArray().Select(group => group.GetProperty("displayName").GetString()).ShouldBe(["Builders", "Admins"]);

        // Across resource types: users first, then groups; an attribute a type doesn't have matches nothing of it.
        var everything = await JsonAsync(await ScimAsync(HttpMethod.Post, ".search", """
            {"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"filter":"displayName sw \"a\"","sortBy":"displayName"}
            """));
        everything.GetProperty("totalResults").GetInt32().ShouldBe(2);
        everything.GetProperty("Resources").EnumerateArray().Select(resource => resource.GetProperty("schemas")[0].GetString()![^5..]).ShouldBe([":User", "Group"]);
        var paged = await JsonAsync(await ScimAsync(HttpMethod.Post, ".search", """
            {"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"startIndex":2,"count":2}
            """));
        paged.GetProperty("totalResults").GetInt32().ShouldBe(4);
        paged.GetProperty("Resources").EnumerateArray().Select(resource => resource.GetProperty("schemas")[0].GetString()![^5..]).ShouldBe([":User", "Group"], "the page spans both types");
        var onlyUsers = await JsonAsync(await ScimAsync(HttpMethod.Post, ".search", """
            {"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"filter":"userName pr"}
            """));
        onlyUsers.GetProperty("totalResults").GetInt32().ShouldBe(2);

        (await ScimAsync(HttpMethod.Post, "Users/.search", """{"filter":"userName pr"}""")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        (await ScimAsync(HttpMethod.Post, ".search", """{"schemas":["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],"sortBy":"password"}""")).StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    private async Task<string> CreateUserAsync(string body)
    {
        var created = await ScimAsync(HttpMethod.Post, "Users", body);
        created.StatusCode.ShouldBe(HttpStatusCode.Created, await created.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return (await JsonAsync(created)).GetProperty("id").GetString()!;
    }

    private async Task ShouldNotFailAsync(HttpMethod method, string path, string? body, string input)
    {
        var response = await ScimAsync(method, path, body);
        ((int)response.StatusCode).ShouldBeLessThan(500, $"{method} {path}: {input}");
    }

    private static readonly string[] FilterTokens =
        ["userName", "USERNAME", "externalId", "displayName", "emails.value", "members[value eq \"x\"]", "eq", "EQ", "ne", "co", "sw", "pr", "gt", "and", "or", "not",
         "(", ")", "[", "]", "\"", "\\\"", "\\", "\"jo@contoso.com\"", "\"\"", " ", "  ", "\u0000", "\u00e9", "🙂", "%", "*", "'", ";--", "true", "null", "1e999"];

    private static string RandomFilter(Random random) =>
        random.Next(10) == 0
            ? new string('(', random.Next(1, 3000))
            : string.Concat(Enumerable.Range(0, random.Next(0, 12)).Select(_ => FilterTokens[random.Next(FilterTokens.Length)] + (random.Next(3) == 0 ? "" : " ")));

    private static readonly string?[] PatchPaths =
        [null, "", "active", "userName", "displayName", "externalId", "name.givenName", "name.familyName", "emails", "emails[type eq \"work\"].value",
         "emails[type eq \"work\"", "members", "members[value eq \"00000000-0000-0000-0000-000000000000\"]", "members[value eq \"not-a-guid\"]",
         "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber", "meta", "id", "groups", "a.b.c.d", "[", "]"];

    private static readonly object?[] PatchOps = ["add", "remove", "replace", "Add", "Replace", "REMOVE", "move", "", null, 7, true];

    private static string RandomPatch(Random random, Guid member)
    {
        if (random.Next(8) == 0)
        {
            return JsonSerializer.Serialize(RandomJson(random, 3, member));
        }

        var operations = Enumerable.Range(0, random.Next(0, 4)).Select(_ =>
        {
            var operation = new Dictionary<string, object?> { ["op"] = PatchOps[random.Next(PatchOps.Length)], ["value"] = RandomJson(random, 2, member) };
            if (random.Next(4) != 0)
            {
                operation["path"] = PatchPaths[random.Next(PatchPaths.Length)];
            }

            return operation;
        }).ToList();
        return JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["schemas"] = new[] { "urn:ietf:params:scim:api:messages:2.0:PatchOp" },
            ["Operations"] = random.Next(10) == 0 ? RandomJson(random, 1, member) : operations,
        });
    }

    private static object? RandomJson(Random random, int depth, Guid member) => random.Next(depth > 0 ? 12 : 8) switch
    {
        0 => null,
        1 => random.Next(2) == 0,
        2 => random.Next(2) == 0 ? "True" : "false",
        3 => random.NextInt64(long.MinValue, long.MaxValue),
        4 => new string((char)random.Next(1, 0xD7FF), random.Next(0, 400)),
        5 => member.ToString(),
        6 => $"{Guid.NewGuid():N}@contoso.com",
        7 => "",
        8 => Enumerable.Range(0, random.Next(0, 4)).Select(_ => RandomJson(random, depth - 1, member)).ToArray(),
        9 => new[] { new Dictionary<string, object?> { ["value"] = RandomJson(random, depth - 1, member), ["type"] = "work", ["primary"] = RandomJson(random, 0, member) } },
        10 => new Dictionary<string, object?> { ["active"] = RandomJson(random, 0, member), ["userName"] = RandomJson(random, 0, member), ["displayName"] = RandomJson(random, 0, member), ["members"] = RandomJson(random, depth - 1, member), ["emails"] = RandomJson(random, depth - 1, member), ["name"] = RandomJson(random, depth - 1, member) },
        _ => Enumerable.Range(0, random.Next(0, 4)).ToDictionary(index => $"k{index}", _ => RandomJson(random, depth - 1, member)),
    };

    [Fact]
    public async Task Without_the_scim_token_policy_tenant_administrators_can_t_create_tokens()
    {
        await StartAsync(scimTokenPolicy: false);

        var refused = await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.ScimTokenRoutes, await AdminAsync(), JsonContent.Create(new { name = "Entra" }));

        refused.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
        (await refused.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).ShouldContain("auth.enterprise.scim_tokens");
    }

    [Fact]
    public async Task Requests_need_a_live_scim_token()
    {
        await StartAsync();

        using var request = new HttpRequestMessage(HttpMethod.Get, "scim/v2/Users");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "scim_not-a-token");
        (await _host.Client.SendAsync(request, TestContext.Current.CancellationToken)).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        var tokens = await (await _host.SendAsync(HttpMethod.Get, EnterpriseEndpointRouteBuilderExtensions.ScimTokenRoutes, await AdminAsync())).Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        var tokenId = tokens[0].GetProperty("id").GetString();
        (await _host.SendAsync(HttpMethod.Delete, $"{EnterpriseEndpointRouteBuilderExtensions.ScimTokenRoutes}/{tokenId}", await AdminAsync())).StatusCode.ShouldBe(HttpStatusCode.NoContent);
        (await ScimAsync(HttpMethod.Get, "Users")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_suspended_or_deleted_tenant_s_scim_token_stops_working()
    {
        await StartAsync();
        (await ScimAsync(HttpMethod.Get, "Users")).StatusCode.ShouldBe(HttpStatusCode.OK);

        _host.Tenants.Tenants[Contoso] = new TenantInfo(Contoso, null, AcceptsSessions: false);
        (await ScimAsync(HttpMethod.Get, "Users")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);

        _host.Tenants.Tenants.TryRemove(Contoso, out _);
        (await ScimAsync(HttpMethod.Get, "Users")).StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    public async ValueTask DisposeAsync()
    {
        if (_host is not null)
        {
            await _host.DisposeAsync();
        }

        TestDatabase.DeleteSqlite(_database);
    }

    // ---- Helpers -------------------------------------------------------------------------------------------------------

    private async Task StartAsync(bool scimTokenPolicy = true)
    {
        _host = await TokenServerHost.StartAsync(
            configure: builder =>
            {
                builder.Services.AddSingleton(_memberships);
                builder.Services.AddScoped<ITenantMembershipProvisioner>(provider => provider.GetRequiredService<RecordingMemberships>());
                builder.Services.AddSingleton<IIntegrationEventHandler<GroupMembershipChangedEvent>>(new Recorder<GroupMembershipChangedEvent>(_events));
                builder.Services.AddSingleton<IIntegrationEventHandler<GroupDeletedEvent>>(new Recorder<GroupDeletedEvent>(_events));
                new AuthenticationBuilder(builder.Services, builder.Configuration).AddEnterprise().UseTestDatabase(_database);
                builder.Services.AddScoped<IEnterpriseDatabaseInitializer, SeedDomain>();
                var policies = builder.Services.AddAuthorizationBuilder().AddPolicy("auth.enterprise.manage", policy => policy.RequireAuthenticatedUser());
                if (scimTokenPolicy)
                {
                    policies.AddPolicy("auth.enterprise.scim_tokens", policy => policy.RequireAuthenticatedUser());
                }
            },
            map: app =>
            {
                app.MapJeffOpsEnterprise();
                app.MapJeffOpsScim();
            });
        _host.Tenants.Tenants[Contoso] = new TenantInfo(Contoso, null, true);

        if (!scimTokenPolicy)
        {
            return;
        }

        var created = await _host.SendAsync(HttpMethod.Post, EnterpriseEndpointRouteBuilderExtensions.ScimTokenRoutes, await AdminAsync(), JsonContent.Create(new { name = "Entra" }));
        created.StatusCode.ShouldBe(HttpStatusCode.OK, await created.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        _token = (await created.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken)).GetProperty("token").GetString()!;
        _token.ShouldStartWith("scim_");
    }

    private async Task<string> AdminAsync()
    {
        var account = await _host.CreateAccountAsync($"admin-{Guid.NewGuid():N}@contoso.com");
        _host.Tenants.Memberships.GetOrAdd(account.Id, _ => []).Add(new TenantMembership(Contoso, null, null, AccessLevel.Tenant));
        return (await _host.SignInAsync(account.Id)).AccessToken!;
    }

    private async Task<HttpResponseMessage> ScimAsync(HttpMethod method, string path, string? body = null, string? ifMatch = null, string? ifNoneMatch = null)
    {
        using var request = new HttpRequestMessage(method, $"scim/v2/{path}");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _token);
        if (ifMatch is not null)
        {
            request.Headers.TryAddWithoutValidation("If-Match", ifMatch);
        }

        if (ifNoneMatch is not null)
        {
            request.Headers.TryAddWithoutValidation("If-None-Match", ifNoneMatch);
        }

        if (body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/scim+json");
        }

        return await _host.Client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private async Task<Guid> UserIdAsync(string email)
    {
        var created = await JsonAsync(await ScimAsync(HttpMethod.Post, "Users", $$"""{"userName":"{{email}}","emails":[{"value":"{{email}}"}]}"""));
        return Guid.Parse(created.GetProperty("id").GetString()!);
    }

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage response)
    {
        response.IsSuccessStatusCode.ShouldBeTrue(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).RootElement.Clone();
    }

    private async Task<Domain.Accounts.Account> AccountAsync(Guid id)
    {
        await using var scope = _host.Services.CreateAsyncScope();
        return (await scope.ServiceProvider.GetRequiredService<IAccountRepository>().FindAsync(id, TestContext.Current.CancellationToken))!;
    }

    private T Last<T>() => _events.OfType<T>().Last();

    /// <summary>Verifies contoso.com for the Contoso tenant, once the schema exists.</summary>
    private sealed class SeedDomain(EnterpriseDbContext db) : IEnterpriseDatabaseInitializer
    {
        public async Task InitializeAsync(CancellationToken cancellationToken)
        {
            if (!await db.Domains.AnyAsync(cancellationToken))
            {
                var domain = Enterprise.Domain.TenantDomain.Claim(Contoso, "contoso.com", DateTimeOffset.UtcNow);
                domain.CheckTxtRecords([domain.ExpectedValue("v=")], "v=", DateTimeOffset.UtcNow).ShouldBeTrue();
                db.Domains.Add(domain);
                await db.SaveChangesAsync(cancellationToken);
            }
        }
    }

    private sealed class Recorder<T>(ConcurrentQueue<IntegrationEvent> events) : IIntegrationEventHandler<T>
        where T : IntegrationEvent
    {
        public Task HandleAsync(T integrationEvent, CancellationToken cancellationToken)
        {
            events.Enqueue(integrationEvent);
            return Task.CompletedTask;
        }
    }
}

internal sealed class RecordingMemberships : ITenantMembershipProvisioner
{
    public ConcurrentQueue<(string Action, Guid TenantId, Guid AccountId)> Calls { get; } = new();

    /// <summary>When set, the tenant system is down.</summary>
    public bool Down { get; set; }

    public Task AddMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken)
    {
        ThrowIfDown();
        Calls.Enqueue(("add", tenantId, accountId));
        return Task.CompletedTask;
    }

    public Task RemoveMemberAsync(Guid tenantId, Guid accountId, CancellationToken cancellationToken)
    {
        ThrowIfDown();
        Calls.Enqueue(("remove", tenantId, accountId));
        return Task.CompletedTask;
    }

    private void ThrowIfDown()
    {
        if (Down)
        {
            throw new HttpRequestException("The tenant system is down.");
        }
    }
}

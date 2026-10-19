using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using JeffOps.Authentication.Enterprise.Application;
using JeffOps.Authentication.Enterprise.Application.Features.Scim;
using JeffOps.Authentication.Enterprise.Application.Features.ScimTokens;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace JeffOps.Authentication.Enterprise.Endpoints;

/// <summary>
/// SCIM 2.0 (RFC 7643/7644) for tenants' identity providers: <c>Users</c> and <c>Groups</c> with create, replace, patch,
/// delete, get and list (filters: <c>userName</c>/<c>externalId</c>/<c>displayName</c> <c>eq</c>), <c>Bulk</c>, ETags
/// (<c>If-Match</c>, <c>If-None-Match</c>), plus the discovery resources. Authenticated with a tenant's SCIM token;
/// everything happens in that tenant.
/// </summary>
public static partial class ScimEndpoints
{
    public const string Root = "scim/v2";
    public const string ContentType = "application/scim+json";

    private const string UserSchema = "urn:ietf:params:scim:schemas:core:2.0:User";
    private const string GroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group";
    private const string ListSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
    private const string ErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error";
    private const string PatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private const string SearchRequestSchema = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
    private const string BulkRequestSchema = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
    private const string BulkResponseSchema = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
    private const string TenantItem = "JeffOps.Scim.Tenant";

    /// <summary>The most operations one <c>Bulk</c> request may carry.</summary>
    public const int MaxBulkOperations = 100;

    /// <summary>The largest <c>Bulk</c> request body, in bytes.</summary>
    public const int MaxBulkPayloadBytes = 1024 * 1024;

    public static IEndpointRouteBuilder MapJeffOpsScim(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var scim = endpoints.MapGroup(Root).WithTags("SCIM").AllowAnonymous().DisableAntiforgery().AddEndpointFilter<ScimTokenFilter>();

        scim.MapGet("ServiceProviderConfig", () => Scim(StatusCodes.Status200OK, ServiceProviderConfig()));
        scim.MapGet("ResourceTypes", () => Scim(StatusCodes.Status200OK, ResourceTypes()));

        scim.MapGet("Users", async Task<IResult> (HttpContext context) => await ListUsersAsync(context, ListRequest.FromQuery(context)).ConfigureAwait(false));
        scim.MapPost("Users/.search", async Task<IResult> (HttpContext context) => await SearchAsync(context, ListUsersAsync).ConfigureAwait(false));
        scim.MapGet("Users/{id}", async Task<IResult> (string id, HttpContext context) => Selected(context, await GetUserAsync(context, id).ConfigureAwait(false)));
        scim.MapPost("Users", async Task<IResult> (HttpContext context) =>
            Selected(context, await CreateUserAsync(context, context.RequestServices, await BodyAsync(context).ConfigureAwait(false)).ConfigureAwait(false)));
        scim.MapPut("Users/{id}", async Task<IResult> (string id, HttpContext context) =>
            Selected(context, await ReplaceUserAsync(context, context.RequestServices, id, await BodyAsync(context).ConfigureAwait(false), IfMatch(context)).ConfigureAwait(false)));
        scim.MapPatch("Users/{id}", async Task<IResult> (string id, HttpContext context) =>
            Selected(context, await PatchUserAsync(context, context.RequestServices, id, await BodyAsync(context).ConfigureAwait(false), IfMatch(context)).ConfigureAwait(false)));
        scim.MapDelete("Users/{id}", async Task<IResult> (string id, HttpContext context) => await DeleteUserAsync(context, context.RequestServices, id, IfMatch(context)).ConfigureAwait(false));

        scim.MapGet("Groups", async Task<IResult> (HttpContext context) => await ListGroupsAsync(context, ListRequest.FromQuery(context)).ConfigureAwait(false));
        scim.MapPost("Groups/.search", async Task<IResult> (HttpContext context) => await SearchAsync(context, ListGroupsAsync).ConfigureAwait(false));
        scim.MapPost(".search", async Task<IResult> (HttpContext context) => await SearchAsync(context, SearchAllAsync).ConfigureAwait(false));
        scim.MapGet("Groups/{id}", async Task<IResult> (string id, HttpContext context) => Selected(context, await GetGroupAsync(context, id).ConfigureAwait(false)));
        scim.MapPost("Groups", async Task<IResult> (HttpContext context) =>
            Selected(context, await CreateGroupAsync(context, context.RequestServices, await BodyAsync(context).ConfigureAwait(false)).ConfigureAwait(false)));
        scim.MapPut("Groups/{id}", async Task<IResult> (string id, HttpContext context) =>
            Selected(context, await ReplaceGroupAsync(context, context.RequestServices, id, await BodyAsync(context).ConfigureAwait(false), IfMatch(context)).ConfigureAwait(false)));
        scim.MapPatch("Groups/{id}", async Task<IResult> (string id, HttpContext context) =>
            Selected(context, await PatchGroupAsync(context, context.RequestServices, id, await BodyAsync(context).ConfigureAwait(false), IfMatch(context)).ConfigureAwait(false)));
        scim.MapDelete("Groups/{id}", async Task<IResult> (string id, HttpContext context) => await DeleteGroupAsync(context, context.RequestServices, id, IfMatch(context)).ConfigureAwait(false));

        scim.MapPost("Bulk", BulkAsync);

        return endpoints;
    }

    // ---- Users ---------------------------------------------------------------------------------------------------------

    private static async Task<IResult> ListUsersAsync(HttpContext context, ListRequest request)
    {
        if (request.Validate() is { } invalid)
        {
            return invalid;
        }

        var result = await context.RequestServices.GetRequiredService<IQueryHandler<ListScimUsersQuery, ScimPage<ScimUserView>>>()
            .HandleAsync(new ListScimUsersQuery(Tenant(context), request.Filter, request.StartIndex, request.Count, request.Sort), context.RequestAborted).ConfigureAwait(false);
        return result.IsSuccess ? Scim(StatusCodes.Status200OK, ListResponse(result.Value, user => Project(UserJson(user, context), request.Selection))) : Error(result.Error);
    }

    private static async Task<ScimResult> GetUserAsync(HttpContext context, string id)
    {
        if (!Guid.TryParse(id, out var userId))
        {
            return NotFound();
        }

        var result = await context.RequestServices.GetRequiredService<IQueryHandler<GetScimUserQuery, ScimUserView>>()
            .HandleAsync(new GetScimUserQuery(Tenant(context), userId), context.RequestAborted).ConfigureAwait(false);
        return result.IsSuccess ? NotModified(context, result.Value.Version) ?? UserResult(result, context) : Error(result.Error);
    }

    private static async Task<ScimResult> CreateUserAsync(HttpContext context, IServiceProvider services, JsonElement? body)
    {
        if (body is not { } given || ParseUser(given) is not { } data)
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "A user needs a userName.");
        }

        var result = await services.GetRequiredService<ICommandHandler<CreateScimUserCommand, ScimUserView>>()
            .HandleAsync(new CreateScimUserCommand(Tenant(context), data), context.RequestAborted).ConfigureAwait(false);
        return result.IsSuccess
            ? Scim(StatusCodes.Status201Created, UserJson(result.Value, context), Location(context, "Users", result.Value.Id), result.Value.Version)
            : Error(result.Error);
    }

    private static async Task<ScimResult> ReplaceUserAsync(HttpContext context, IServiceProvider services, string id, JsonElement? body, IReadOnlyList<int>? ifMatch)
    {
        if (!Guid.TryParse(id, out var userId))
        {
            return NotFound();
        }

        if (body is not { } given || ParseUser(given) is not { } data)
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "A user needs a userName.");
        }

        return UserResult(await services.GetRequiredService<ICommandHandler<UpdateScimUserCommand, ScimUserView>>()
            .HandleAsync(new UpdateScimUserCommand(Tenant(context), userId, _ => data, ifMatch), context.RequestAborted).ConfigureAwait(false), context);
    }

    private static async Task<ScimResult> PatchUserAsync(HttpContext context, IServiceProvider services, string id, JsonElement? body, IReadOnlyList<int>? ifMatch)
    {
        if (!Guid.TryParse(id, out var userId))
        {
            return NotFound();
        }

        if (body is not { } given || !Has(given, "Operations", out var operations) || operations.ValueKind != JsonValueKind.Array)
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "A PATCH needs Operations.");
        }

        var ops = operations.Clone();
        return UserResult(await services.GetRequiredService<ICommandHandler<UpdateScimUserCommand, ScimUserView>>()
            .HandleAsync(new UpdateScimUserCommand(Tenant(context), userId, current => ApplyUserPatch(current, ops), ifMatch), context.RequestAborted).ConfigureAwait(false), context);
    }

    private static async Task<ScimResult> DeleteUserAsync(HttpContext context, IServiceProvider services, string id, IReadOnlyList<int>? ifMatch) =>
        !Guid.TryParse(id, out var userId)
            ? NotFound()
            : NoContent(await services.GetRequiredService<ICommandHandler<DeleteScimUserCommand>>()
                .HandleAsync(new DeleteScimUserCommand(Tenant(context), userId, ifMatch), context.RequestAborted).ConfigureAwait(false));

    private static ScimUserData? ParseUser(JsonElement body)
    {
        if (Text(body, "userName") is not { } userName)
        {
            return null;
        }

        var name = Has(body, "name", out var nameElement) && nameElement.ValueKind == JsonValueKind.Object ? nameElement : default;
        return new ScimUserData(
            userName,
            Text(body, "externalId"),
            name.ValueKind == JsonValueKind.Object ? Text(name, "givenName") : null,
            name.ValueKind == JsonValueKind.Object ? Text(name, "familyName") : null,
            Text(body, "displayName"),
            PrimaryEmail(body),
            !Has(body, "active", out var active) || Bool(active) != false);
    }

    /// <summary>
    /// Applies PATCH operations (RFC 7644 §3.5.2) to a user: <c>active</c>, <c>userName</c>, <c>displayName</c>,
    /// <c>externalId</c>, <c>name.givenName</c>, <c>name.familyName</c> and <c>emails</c>, with or without a path (Entra sends
    /// both forms, and booleans as strings).
    /// </summary>
    private static Result<ScimUserData> ApplyUserPatch(ScimUserData current, JsonElement operations)
    {
        var data = current;
        foreach (var operation in operations.EnumerateArray())
        {
            var op = Text(operation, "op")?.ToLowerInvariant();
            var path = Text(operation, "path");
            var hasValue = Has(operation, "value", out var value);

            if (op is not ("add" or "replace" or "remove"))
            {
                return JeffOps.Authentication.SharedKernel.Results.Error.Failure(ScimErrors.InvalidValue, $"Unsupported op '{op}'.");
            }

            if (path is null)
            {
                if (!hasValue || value.ValueKind != JsonValueKind.Object)
                {
                    return JeffOps.Authentication.SharedKernel.Results.Error.Failure(ScimErrors.InvalidValue, "An operation without a path needs an object value.");
                }

                foreach (var property in value.EnumerateObject())
                {
                    data = SetUserAttribute(data, property.Name, op == "remove" ? default : property.Value);
                }

                continue;
            }

            data = SetUserAttribute(data, path, op == "remove" ? default : value);
        }

        return data;
    }

    private static ScimUserData SetUserAttribute(ScimUserData data, string path, JsonElement value)
    {
        var text = value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Undefined or JsonValueKind.Null => null,
            _ => value.ToString(),
        };

        return path.ToLowerInvariant() switch
        {
            "active" => data with { Active = Bool(value) ?? data.Active },
            "username" when text is not null => data with { UserName = text },
            "displayname" => data with { DisplayName = text },
            "externalid" => data with { ExternalId = text },
            "name.givenname" => data with { GivenName = text },
            "name.familyname" => data with { FamilyName = text },
            "name" when value.ValueKind == JsonValueKind.Object => data with { GivenName = Text(value, "givenName") ?? data.GivenName, FamilyName = Text(value, "familyName") ?? data.FamilyName },
            "emails" when value.ValueKind == JsonValueKind.Array => data with { Email = PrimaryEmail(JsonDocument.Parse($"{{\"emails\":{value.GetRawText()}}}").RootElement) ?? data.Email },
            var other when other.StartsWith("emails[", StringComparison.Ordinal) && text is not null => data with { Email = text },
            _ => data,
        };
    }

    private static ScimResult UserResult(Result<ScimUserView> result, HttpContext context) =>
        result.IsSuccess ? Scim(StatusCodes.Status200OK, UserJson(result.Value, context), version: result.Value.Version) : Error(result.Error);

    private static JsonObject UserJson(ScimUserView user, HttpContext context) => new()
    {
        ["schemas"] = new JsonArray(UserSchema),
        ["id"] = user.Id.ToString(),
        ["externalId"] = user.ExternalId,
        ["userName"] = user.UserName,
        ["displayName"] = user.DisplayName,
        ["name"] = new JsonObject { ["givenName"] = user.GivenName, ["familyName"] = user.FamilyName },
        ["emails"] = new JsonArray(new JsonObject { ["value"] = user.Email, ["primary"] = true, ["type"] = "work" }),
        ["active"] = user.Active,
        ["groups"] = new JsonArray([.. user.Groups.Select(group => (JsonNode)new JsonObject { ["value"] = group.Id.ToString(), ["display"] = group.DisplayName })]),
        ["meta"] = Meta("User", user.Created, user.LastModified, user.Version, Location(context, "Users", user.Id)),
    };

    // ---- Groups --------------------------------------------------------------------------------------------------------

    private static async Task<IResult> ListGroupsAsync(HttpContext context, ListRequest request)
    {
        if (request.Validate() is { } invalid)
        {
            return invalid;
        }

        var result = await context.RequestServices.GetRequiredService<IQueryHandler<ListScimGroupsQuery, ScimPage<ScimGroupView>>>()
            .HandleAsync(new ListScimGroupsQuery(Tenant(context), request.Filter, request.StartIndex, request.Count, request.Sort, !Excludes(request.Selection, "members")), context.RequestAborted).ConfigureAwait(false);
        return result.IsSuccess ? Scim(StatusCodes.Status200OK, ListResponse(result.Value, group => Project(GroupJson(group, context), request.Selection))) : Error(result.Error);
    }

    // ---- Search --------------------------------------------------------------------------------------------------------

    /// <summary><c>POST …/.search</c> (RFC 7644 §3.4.3): the list parameters in a SearchRequest body instead of the query.</summary>
    private static async Task<IResult> SearchAsync(HttpContext context, Func<HttpContext, ListRequest, Task<IResult>> list)
    {
        if (await BodyAsync(context).ConfigureAwait(false) is not { } body || !Has(body, "schemas", out var schemas) || schemas.ValueKind != JsonValueKind.Array
            || !schemas.EnumerateArray().Any(schema => schema.ValueKind == JsonValueKind.String && schema.GetString() == SearchRequestSchema))
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidSyntax, "A search needs a SearchRequest body.");
        }

        return await list(context, ListRequest.FromSearch(body)).ConfigureAwait(false);
    }

    /// <summary><c>POST /.search</c>: users and groups together.</summary>
    private static async Task<IResult> SearchAllAsync(HttpContext context, ListRequest request)
    {
        if (request.Validate() is { } invalid)
        {
            return invalid;
        }

        var result = await context.RequestServices.GetRequiredService<IQueryHandler<SearchScimQuery, ScimSearchPage>>()
            .HandleAsync(new SearchScimQuery(Tenant(context), request.Filter, request.StartIndex, request.Count, request.Sort, !Excludes(request.Selection, "members")), context.RequestAborted).ConfigureAwait(false);
        if (result.IsFailure)
        {
            return Error(result.Error);
        }

        var page = result.Value;
        var resources = page.Users.Select(user => (JsonNode)Project(UserJson(user, context), request.Selection))
            .Concat(page.Groups.Select(group => (JsonNode)Project(GroupJson(group, context), request.Selection)))
            .ToList();
        return Scim(StatusCodes.Status200OK, new JsonObject
        {
            ["schemas"] = new JsonArray(ListSchema),
            ["totalResults"] = page.TotalResults,
            ["startIndex"] = page.StartIndex,
            ["itemsPerPage"] = resources.Count,
            ["Resources"] = new JsonArray([.. resources]),
        });
    }

    /// <summary>A list's parameters (RFC 7644 §3.4.2), from the query string or a SearchRequest body.</summary>
    private sealed record ListRequest(Result<ScimFilter?> ParsedFilter, string? SortBy, string? SortOrder, int StartIndex, int Count, AttributeSelection? Selection)
    {
        public ScimFilter? Filter => ParsedFilter.IsSuccess ? ParsedFilter.Value : null;

        public ScimSort? Sort => AttributeName(SortBy) is { } attribute
            ? new ScimSort(attribute, string.Equals(SortOrder, "descending", StringComparison.OrdinalIgnoreCase))
            : null;

        public static ListRequest FromQuery(HttpContext context)
        {
            var query = context.Request.Query;
            return new(
                ScimEndpoints.Filter(query["filter"].ToString()),
                query["sortBy"].ToString(),
                query["sortOrder"].ToString(),
                int.TryParse(query["startIndex"], NumberStyles.Integer, CultureInfo.InvariantCulture, out var start) ? start : 1,
                int.TryParse(query["count"], NumberStyles.Integer, CultureInfo.InvariantCulture, out var count) ? count : 100,
                ScimEndpoints.Selection(query["attributes"].ToString(), query["excludedAttributes"].ToString()));
        }

        public static ListRequest FromSearch(JsonElement body) => new(
            ScimEndpoints.Filter(Text(body, "filter")),
            Text(body, "sortBy"),
            Text(body, "sortOrder"),
            Has(body, "startIndex", out var start) && start.ValueKind == JsonValueKind.Number && start.TryGetInt32(out var startIndex) ? startIndex : 1,
            Has(body, "count", out var count) && count.ValueKind == JsonValueKind.Number && count.TryGetInt32(out var size) ? size : 100,
            ScimEndpoints.Selection(Names(body, "attributes"), Names(body, "excludedAttributes")));

        /// <summary>A SCIM error for parameters that can't be used; null when they can.</summary>
        public ScimResult? Validate()
        {
            if (ParsedFilter.IsFailure)
            {
                return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidFilter, ParsedFilter.Error.Message);
            }

            return !string.IsNullOrEmpty(SortOrder) && !SortOrder.Equals("ascending", StringComparison.OrdinalIgnoreCase) && !SortOrder.Equals("descending", StringComparison.OrdinalIgnoreCase)
                ? Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "sortOrder is 'ascending' or 'descending'.")
                : null;
        }

        /// <summary>A body's attribute list: an array of names, or one comma-separated string.</summary>
        private static string Names(JsonElement body, string property) =>
            Has(body, property, out var value) && value.ValueKind == JsonValueKind.Array
                ? string.Join(',', value.EnumerateArray().Where(name => name.ValueKind == JsonValueKind.String).Select(name => name.GetString()))
                : Text(body, property) ?? string.Empty;
    }

    private static async Task<ScimResult> GetGroupAsync(HttpContext context, string id)
    {
        if (!Guid.TryParse(id, out var groupId))
        {
            return NotFound();
        }

        var result = await context.RequestServices.GetRequiredService<IQueryHandler<GetScimGroupQuery, ScimGroupView>>()
            .HandleAsync(new GetScimGroupQuery(Tenant(context), groupId), context.RequestAborted).ConfigureAwait(false);
        return result.IsSuccess ? NotModified(context, result.Value.Version) ?? GroupResult(result, context) : Error(result.Error);
    }

    private static async Task<ScimResult> CreateGroupAsync(HttpContext context, IServiceProvider services, JsonElement? given)
    {
        if (given is not { } body || Text(body, "displayName") is not { } displayName)
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "A group needs a displayName.");
        }

        if (!TryMembers(Has(body, "members", out var members) ? members : default, out var memberIds))
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "Member values must be user ids.");
        }

        var result = await services.GetRequiredService<ICommandHandler<CreateScimGroupCommand, ScimGroupView>>()
            .HandleAsync(new CreateScimGroupCommand(Tenant(context), displayName, Text(body, "externalId"), memberIds), context.RequestAborted).ConfigureAwait(false);
        return result.IsSuccess
            ? Scim(StatusCodes.Status201Created, GroupJson(result.Value, context), Location(context, "Groups", result.Value.Id), result.Value.Version)
            : Error(result.Error);
    }

    private static async Task<ScimResult> ReplaceGroupAsync(HttpContext context, IServiceProvider services, string id, JsonElement? given, IReadOnlyList<int>? ifMatch)
    {
        if (!Guid.TryParse(id, out var groupId))
        {
            return NotFound();
        }

        if (given is not { } body || Text(body, "displayName") is not { } displayName
            || !TryMembers(Has(body, "members", out var members) ? members : default, out var memberIds))
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "A group needs a displayName and user ids as members.");
        }

        var change = new ScimGroupChange(displayName, Text(body, "externalId"), ReplaceMembers: memberIds);
        return GroupResult(await services.GetRequiredService<ICommandHandler<UpdateScimGroupCommand, ScimGroupView>>()
            .HandleAsync(new UpdateScimGroupCommand(Tenant(context), groupId, change, ifMatch), context.RequestAborted).ConfigureAwait(false), context);
    }

    private static async Task<ScimResult> PatchGroupAsync(HttpContext context, IServiceProvider services, string id, JsonElement? given, IReadOnlyList<int>? ifMatch)
    {
        if (!Guid.TryParse(id, out var groupId))
        {
            return NotFound();
        }

        if (given is not { } body || !Has(body, "Operations", out var operations) || operations.ValueKind != JsonValueKind.Array)
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "A PATCH needs Operations.");
        }

        string? displayName = null;
        string? externalId = null;
        List<Guid>? replace = null;
        var add = new List<Guid>();
        var remove = new List<Guid>();

        foreach (var operation in operations.EnumerateArray())
        {
            var op = Text(operation, "op")?.ToLowerInvariant();
            var path = Text(operation, "path");
            var value = Has(operation, "value", out var v) ? v : default;

            if (path is null && value.ValueKind == JsonValueKind.Object)
            {
                displayName = Text(value, "displayName") ?? displayName;
                externalId = Text(value, "externalId") ?? externalId;
                if (Has(value, "members", out var objectMembers))
                {
                    if (!TryMembers(objectMembers, out var ids))
                    {
                        return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "Member values must be user ids.");
                    }

                    (op switch { "add" => add, "remove" => remove, _ => null })?.AddRange(ids);
                    replace = op == "replace" ? [.. ids] : replace;
                }

                continue;
            }

            if (path is not null && MemberFilter().Match(path) is { Success: true } single)
            {
                if (op != "remove" || !Guid.TryParse(single.Groups[1].Value, out var memberId))
                {
                    return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "Only 'remove' supports a member filter path.");
                }

                remove.Add(memberId);
                continue;
            }

            switch (path?.ToLowerInvariant(), op)
            {
                case ("displayname", "replace" or "add"):
                    displayName = value.ValueKind == JsonValueKind.String ? value.GetString() : displayName;
                    break;
                case ("externalid", "replace" or "add"):
                    externalId = value.ValueKind == JsonValueKind.String ? value.GetString() : externalId;
                    break;
                case ("members", var memberOp):
                    if (value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null && memberOp == "remove")
                    {
                        replace = [];
                        break;
                    }

                    if (!TryMembers(value, out var ids))
                    {
                        return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "Member values must be user ids.");
                    }

                    switch (memberOp)
                    {
                        case "add": add.AddRange(ids); break;
                        case "remove": remove.AddRange(ids); break;
                        case "replace": replace = [.. ids]; break;
                    }

                    break;
                default:
                    return Error(StatusCodes.Status400BadRequest, ScimErrors.NoTarget, $"Unsupported operation '{op}' on '{path}'.");
            }
        }

        var change = new ScimGroupChange(displayName, externalId, replace, add.Count > 0 ? add : null, remove.Count > 0 ? remove : null);
        return GroupResult(await services.GetRequiredService<ICommandHandler<UpdateScimGroupCommand, ScimGroupView>>()
            .HandleAsync(new UpdateScimGroupCommand(Tenant(context), groupId, change, ifMatch), context.RequestAborted).ConfigureAwait(false), context);
    }

    private static async Task<ScimResult> DeleteGroupAsync(HttpContext context, IServiceProvider services, string id, IReadOnlyList<int>? ifMatch) =>
        !Guid.TryParse(id, out var groupId)
            ? NotFound()
            : NoContent(await services.GetRequiredService<ICommandHandler<DeleteScimGroupCommand>>()
                .HandleAsync(new DeleteScimGroupCommand(Tenant(context), groupId, ifMatch), context.RequestAborted).ConfigureAwait(false));

    private static ScimResult GroupResult(Result<ScimGroupView> result, HttpContext context) =>
        result.IsSuccess ? Scim(StatusCodes.Status200OK, GroupJson(result.Value, context), version: result.Value.Version) : Error(result.Error);

    private static JsonObject GroupJson(ScimGroupView group, HttpContext context)
    {
        var json = new JsonObject
        {
            ["schemas"] = new JsonArray(GroupSchema),
            ["id"] = group.Id.ToString(),
            ["externalId"] = group.ExternalId,
            ["displayName"] = group.DisplayName,
            ["meta"] = Meta("Group", group.Created, group.LastModified, group.Version, Location(context, "Groups", group.Id)),
        };
        json["members"] = new JsonArray([.. group.Members.Select(member => (JsonNode)new JsonObject { ["value"] = member.ToString(), ["$ref"] = Location(context, "Users", member) })]);
        return json;
    }

    private static bool TryMembers(JsonElement members, out List<Guid> ids)
    {
        ids = [];
        if (members.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
        {
            return true;
        }

        if (members.ValueKind != JsonValueKind.Array)
        {
            return false;
        }

        foreach (var member in members.EnumerateArray())
        {
            if (Text(member, "value") is not { } value || !Guid.TryParse(value, out var id))
            {
                return false;
            }

            ids.Add(id);
        }

        return true;
    }

    // ---- Bulk ----------------------------------------------------------------------------------------------------------

    /// <summary>
    /// Bulk (RFC 7644 §3.7): up to <see cref="MaxBulkOperations"/> operations in order, each in its own unit of work, so one
    /// failure leaves the others as they are. <c>bulkId:{id}</c> in a path or a value refers to a resource an earlier
    /// operation of the same request created. <c>failOnErrors</c> stops after that many errors; <c>version</c> works as
    /// <c>If-Match</c>.
    /// </summary>
    private static async Task<IResult> BulkAsync(HttpContext context, IServiceScopeFactory scopes, ILoggerFactory loggers)
    {
        if (context.Request.ContentLength > MaxBulkPayloadBytes)
        {
            return Error(StatusCodes.Status413PayloadTooLarge, null, $"A bulk request is at most {MaxBulkPayloadBytes} bytes.");
        }

        JsonElement request;
        try
        {
            if (await LimitedBodyAsync(context, MaxBulkPayloadBytes).ConfigureAwait(false) is not { } body)
            {
                return Error(StatusCodes.Status413PayloadTooLarge, null, $"A bulk request is at most {MaxBulkPayloadBytes} bytes.");
            }

            request = body;
        }
        catch (JsonException)
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidSyntax, "The request is not JSON.");
        }

        if (request.ValueKind != JsonValueKind.Object || !Has(request, "schemas", out var schemas) || schemas.ValueKind != JsonValueKind.Array
            || !schemas.EnumerateArray().Any(schema => schema.ValueKind == JsonValueKind.String && schema.GetString() == BulkRequestSchema)
            || !Has(request, "Operations", out var operations) || operations.ValueKind != JsonValueKind.Array)
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidSyntax, "A bulk request needs the BulkRequest schema and Operations.");
        }

        if (operations.GetArrayLength() > MaxBulkOperations)
        {
            return Error(StatusCodes.Status413PayloadTooLarge, null, $"A bulk request has at most {MaxBulkOperations} operations.");
        }

        var failOnErrors = Has(request, "failOnErrors", out var limit) && limit.ValueKind == JsonValueKind.Number && limit.TryGetInt32(out var errors) && errors > 0 ? errors : (int?)null;
        var created = new Dictionary<string, (string Resource, string Id)>(StringComparer.Ordinal);
        var logger = loggers.CreateLogger("JeffOps.Authentication.Enterprise.Scim");
        var pending = operations.EnumerateArray()
            .Select((operation, index) => new PendingOperation(
                index,
                operation,
                Text(operation, "method")?.ToUpperInvariant() ?? string.Empty,
                Text(operation, "bulkId"),
                BulkReferences(operation)))
            .ToList();
        var results = new JsonObject?[pending.Count];
        var errorCount = 0;

        // Operations run as written, except that one referring to a bulkId waits for the operation that creates it (RFC 7644
        // §3.7.2: forward references). References that can never resolve (a cycle) are reported, not run.
        while (pending.Count > 0 && !(failOnErrors is { } stopAt && errorCount >= stopAt))
        {
            var definedLater = pending.Where(operation => operation.Method == "POST" && operation.BulkId is not null).Select(operation => operation.BulkId!).ToHashSet(StringComparer.Ordinal);
            var next = pending.FirstOrDefault(operation => !operation.References.Any(definedLater.Contains));
            var outcome = next is null
                ? (Result: Error(StatusCodes.Status409Conflict, ScimErrors.InvalidValue, "Circular bulkId references can't be resolved."), Location: (string?)null)
                : await BulkOperationAsync(context, scopes, logger, next.Operation, next.Method, next.BulkId, created).ConfigureAwait(false);
            var current = next ?? pending[0];
            pending.Remove(current);
            var method = current.Method;
            var bulkId = current.BulkId;

            var entry = new JsonObject { ["method"] = method, ["status"] = outcome.Result.Status.ToString(CultureInfo.InvariantCulture) };
            if (bulkId is not null)
            {
                entry["bulkId"] = bulkId;
            }

            if (outcome.Location is not null)
            {
                entry["location"] = outcome.Location;
            }

            if (outcome.Result.Version is { } version)
            {
                entry["version"] = ETag(version);
            }

            if (outcome.Result.Status >= 400)
            {
                errorCount++;
                entry["response"] = outcome.Result.Body?.DeepClone();
            }

            results[current.Index] = entry;
        }

        // In the order the client sent them; operations not run (after failOnErrors) are left out.
        return Scim(StatusCodes.Status200OK, new JsonObject
        {
            ["schemas"] = new JsonArray(BulkResponseSchema),
            ["Operations"] = new JsonArray([.. results.Where(entry => entry is not null).Cast<JsonNode>()]),
        });
    }

    private sealed record PendingOperation(int Index, JsonElement Operation, string Method, string? BulkId, IReadOnlySet<string> References);

    /// <summary>The bulkIds an operation refers to, in its path or anywhere in its data.</summary>
    private static HashSet<string> BulkReferences(JsonElement operation)
    {
        var references = new HashSet<string>(StringComparer.Ordinal);
        void Visit(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.String when element.GetString() is { } text && text.StartsWith("bulkId:", StringComparison.Ordinal):
                    references.Add(text["bulkId:".Length..]);
                    break;
                case JsonValueKind.Object:
                    foreach (var property in element.EnumerateObject())
                    {
                        Visit(property.Value);
                    }

                    break;
                case JsonValueKind.Array:
                    foreach (var item in element.EnumerateArray())
                    {
                        Visit(item);
                    }

                    break;
            }
        }

        if (operation.ValueKind == JsonValueKind.Object)
        {
            if (Has(operation, "data", out var data))
            {
                Visit(data);
            }

            foreach (var segment in (Text(operation, "path") ?? string.Empty).Split('/'))
            {
                if (segment.StartsWith("bulkId:", StringComparison.Ordinal))
                {
                    references.Add(segment["bulkId:".Length..]);
                }
            }
        }

        return references;
    }

    private static async Task<(ScimResult Result, string? Location)> BulkOperationAsync(
        HttpContext context, IServiceScopeFactory scopes, ILogger logger, JsonElement operation, string method, string? bulkId, Dictionary<string, (string Resource, string Id)> created)
    {
        if (method == "POST" && (bulkId is null || created.ContainsKey(bulkId)))
        {
            return (Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, bulkId is null ? "A POST needs a bulkId." : $"bulkId '{bulkId}' is used twice."), null);
        }

        if (BulkPath(Text(operation, "path"), created) is not { } path)
        {
            return (Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidPath, "The path must be /Users or /Groups (for POST), or /Users/{id} or /Groups/{id}, with bulkIds of earlier operations only."), null);
        }

        JsonElement? data = null;
        if (Has(operation, "data", out var given))
        {
            if (Resolve(JsonNode.Parse(given.GetRawText()), created) is not { } resolved)
            {
                return (Error(StatusCodes.Status409Conflict, ScimErrors.InvalidValue, "The data refers to a bulkId no earlier operation created."), null);
            }

            data = JsonSerializer.SerializeToElement(resolved);
        }

        var ifMatch = Text(operation, "version") is { } version ? Versions(version) : null;
        ScimResult result;
        try
        {
            // Each operation in its own scope: a failed one leaves nothing half-done for the next to save.
            var scope = scopes.CreateAsyncScope();
            await using (scope.ConfigureAwait(false))
            {
                var services = scope.ServiceProvider;
                result = await ((method, path.Resource, path.Id) switch
                {
                    ("POST", "Users", null) => CreateUserAsync(context, services, data),
                    ("POST", "Groups", null) => CreateGroupAsync(context, services, data),
                    ("PUT", "Users", { } id) => ReplaceUserAsync(context, services, id, data, ifMatch),
                    ("PUT", "Groups", { } id) => ReplaceGroupAsync(context, services, id, data, ifMatch),
                    ("PATCH", "Users", { } id) => PatchUserAsync(context, services, id, data, ifMatch),
                    ("PATCH", "Groups", { } id) => PatchGroupAsync(context, services, id, data, ifMatch),
                    ("DELETE", "Users", { } id) => DeleteUserAsync(context, services, id, ifMatch),
                    ("DELETE", "Groups", { } id) => DeleteGroupAsync(context, services, id, ifMatch),
                    _ => Task.FromResult(Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidPath, $"'{method}' isn't supported on '{Text(operation, "path")}'.")),
                }).ConfigureAwait(false);
            }
        }
#pragma warning disable CA1031 // One operation's failure is reported in its result; the others still run.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            LogBulkOperationFailed(logger, exception, method, Text(operation, "path"));
            result = Error(StatusCodes.Status500InternalServerError, null, "The operation failed.");
        }

        if (method == "POST" && result.Status == StatusCodes.Status201Created && result.Body?["id"]?.GetValue<string>() is { } createdId)
        {
            created[bulkId!] = (path.Resource, createdId);
        }

        var location = result.Location
            ?? (path.Id is { } existing && result.Status < 400 ? $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/{Root}/{path.Resource}/{existing}" : null);
        return (result, location);
    }

    /// <summary>The resource and id a bulk path names, with a <c>bulkId:</c> id resolved; null when it isn't a supported path.</summary>
    private static (string Resource, string? Id)? BulkPath(string? path, Dictionary<string, (string Resource, string Id)> created)
    {
        var parts = (path ?? string.Empty).Trim('/').Split('/');
        var resource = parts[0] switch
        {
            var users when users.Equals("Users", StringComparison.OrdinalIgnoreCase) => "Users",
            var groups when groups.Equals("Groups", StringComparison.OrdinalIgnoreCase) => "Groups",
            _ => null,
        };
        if (resource is null || parts.Length > 2)
        {
            return null;
        }

        if (parts.Length == 1)
        {
            return (resource, null);
        }

        if (parts[1].StartsWith("bulkId:", StringComparison.Ordinal))
        {
            return created.TryGetValue(parts[1]["bulkId:".Length..], out var target) && target.Resource == resource ? (resource, target.Id) : null;
        }

        return (resource, parts[1]);
    }

    /// <summary>Replaces <c>bulkId:{id}</c> strings with the ids of resources created earlier; null when one isn't known.</summary>
    private static JsonNode? Resolve(JsonNode? node, Dictionary<string, (string Resource, string Id)> created)
    {
        switch (node)
        {
            case JsonValue value when value.TryGetValue<string>(out var text) && text.StartsWith("bulkId:", StringComparison.Ordinal):
                return created.TryGetValue(text["bulkId:".Length..], out var target) ? JsonValue.Create(target.Id) : null;
            case JsonObject obj:
                foreach (var (key, value) in obj.ToList())
                {
                    if (value is null)
                    {
                        continue;
                    }

                    if (Resolve(value, created) is not { } resolved)
                    {
                        return null;
                    }

                    if (!ReferenceEquals(resolved, value))
                    {
                        obj[key] = resolved;
                    }
                }

                return obj;
            case JsonArray array:
                for (var index = 0; index < array.Count; index++)
                {
                    if (array[index] is { } item)
                    {
                        if (Resolve(item, created) is not { } resolved)
                        {
                            return null;
                        }

                        if (!ReferenceEquals(resolved, item))
                        {
                            array[index] = resolved;
                        }
                    }
                }

                return array;
            default:
                return node;
        }
    }

    private static async Task<JsonElement?> LimitedBodyAsync(HttpContext context, int maxBytes)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await context.Request.Body.ReadAsync(chunk, context.RequestAborted).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > maxBytes)
            {
                return null;
            }

            buffer.Write(chunk, 0, read);
        }

        using var document = JsonDocument.Parse(buffer.ToArray());
        return document.RootElement.Clone();
    }

    [LoggerMessage(EventId = 8701, Level = LogLevel.Error, Message = "A SCIM bulk operation ({Method} {Path}) failed.")]
    private static partial void LogBulkOperationFailed(ILogger logger, Exception exception, string method, string? path);

    // ---- ETags ---------------------------------------------------------------------------------------------------------

    private static string ETag(int version) => $"W/\"{version.ToString(CultureInfo.InvariantCulture)}\"";

    /// <summary>The versions <c>If-Match</c> allows; null when there is no precondition or it is <c>*</c>.</summary>
    private static IReadOnlyList<int>? IfMatch(HttpContext context) => Versions(context.Request.Headers.IfMatch.ToString());

    /// <summary>
    /// The versions in a list of entity tags (weak or strong, as both name the same version here); null for none or <c>*</c>.
    /// Tags that aren't this server's leave the list empty, so they match nothing.
    /// </summary>
    private static IReadOnlyList<int>? Versions(string? header)
    {
        if (string.IsNullOrWhiteSpace(header))
        {
            return null;
        }

        var versions = new List<int>();
        foreach (var tag in header.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (tag == "*")
            {
                return null;
            }

            var quoted = tag.StartsWith("W/", StringComparison.Ordinal) ? tag[2..] : tag;
            if (quoted.Length > 2 && quoted[0] == '"' && quoted[^1] == '"'
                && int.TryParse(quoted[1..^1], NumberStyles.None, CultureInfo.InvariantCulture, out var version))
            {
                versions.Add(version);
            }
        }

        return versions;
    }

    /// <summary>304 when <c>If-None-Match</c> names the current version (or is <c>*</c>); null to send the resource.</summary>
    private static ScimResult? NotModified(HttpContext context, int version)
    {
        var header = context.Request.Headers.IfNoneMatch.ToString();
        if (string.IsNullOrWhiteSpace(header))
        {
            return null;
        }

        return header.Trim() == "*" || Versions(header) is { } versions && versions.Contains(version)
            ? new ScimResult(StatusCodes.Status304NotModified, null, null, version)
            : null;
    }

    // ---- Sorting and attribute selection ---------------------------------------------------------------------------

    /// <summary>What <c>attributes</c> or <c>excludedAttributes</c> (RFC 7644 §3.9) ask for: dotted paths, lower-cased.</summary>
    private sealed record AttributeSelection(IReadOnlyList<string[]>? Include, IReadOnlyList<string[]> Exclude);

    private static AttributeSelection? Selection(HttpContext context) =>
        Selection(context.Request.Query["attributes"].ToString(), context.Request.Query["excludedAttributes"].ToString());

    private static AttributeSelection? Selection(string attributes, string excludedAttributes)
    {
        var include = Paths(attributes);
        var exclude = Paths(excludedAttributes);
        return include is null && exclude is null ? null : new AttributeSelection(include, exclude ?? []);
    }

    private static List<string[]>? Paths(string raw)
    {
        var paths = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(AttributeName)
            .Where(name => name is not null)
            .Select(name => name!.ToLowerInvariant().Split('.'))
            .ToList();
        return paths.Count == 0 ? null : paths;
    }

    /// <summary>An attribute name without its schema (<c>urn:…:User:name.givenName</c> is <c>name.givenName</c>); null for none.</summary>
    private static string? AttributeName(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var trimmed = raw.Trim();
        return trimmed.StartsWith("urn:", StringComparison.OrdinalIgnoreCase) ? trimmed[(trimmed.LastIndexOf(':') + 1)..] : trimmed;
    }

    /// <summary>Whether the answer leaves <paramref name="attribute"/> out entirely, so it needn't be read.</summary>
    private static bool Excludes(AttributeSelection? selection, string attribute) =>
        selection is not null
        && (selection.Include is { } include
            ? !include.Any(path => path[0] == attribute)
            : selection.Exclude.Any(path => path.Length == 1 && path[0] == attribute));

    /// <summary>The single-resource answer with only the attributes the request selects (POST, PUT, PATCH and GET alike).</summary>
    private static ScimResult Selected(HttpContext context, ScimResult result) =>
        result.Status < 300 && result.Body is { } body && Selection(context) is { } selection
            ? new ScimResult(result.Status, Project(body, selection), result.Location, result.Version)
            : result;

    /// <summary>
    /// The resource with only the selected attributes: <c>attributes</c> keeps those named (and sub-attributes of them),
    /// <c>excludedAttributes</c> drops those named; <c>id</c> and <c>schemas</c> are always returned.
    /// </summary>
    private static JsonObject Project(JsonObject resource, AttributeSelection? selection)
    {
        if (selection is null)
        {
            return resource;
        }

        var projected = new JsonObject();
        foreach (var (name, value) in resource)
        {
            var key = name.ToLowerInvariant();
            if (key is "id" or "schemas")
            {
                projected[name] = value?.DeepClone();
                continue;
            }

            if (selection.Include is { } include)
            {
                if (include.Any(path => path.Length == 1 && path[0] == key))
                {
                    projected[name] = value?.DeepClone();
                }
                else if (include.Where(path => path.Length == 2 && path[0] == key).Select(path => path[1]).ToHashSet(StringComparer.Ordinal) is { Count: > 0 } keep
                    && Within(value, keep, keeping: true) is { } kept)
                {
                    projected[name] = kept;
                }

                continue;
            }

            if (selection.Exclude.Any(path => path.Length == 1 && path[0] == key))
            {
                continue;
            }

            var drop = selection.Exclude.Where(path => path.Length == 2 && path[0] == key).Select(path => path[1]).ToHashSet(StringComparer.Ordinal);
            projected[name] = drop.Count > 0 ? Within(value, drop, keeping: false) : value?.DeepClone();
        }

        return projected;
    }

    /// <summary>A complex (or multi-valued complex) attribute with only, or without, the named sub-attributes.</summary>
    private static JsonNode? Within(JsonNode? value, HashSet<string> names, bool keeping) => value switch
    {
        JsonObject complex => new JsonObject(complex
            .Where(pair => names.Contains(pair.Key.ToLowerInvariant()) == keeping)
            .Select(pair => KeyValuePair.Create(pair.Key, pair.Value?.DeepClone()))),
        JsonArray values => new JsonArray([.. values.Select(item => Within(item, names, keeping))]),
        _ => keeping ? null : value?.DeepClone(),
    };

    // ---- Protocol helpers ----------------------------------------------------------------------------------------------

    private static Guid Tenant(HttpContext context) => (Guid)context.Items[TenantItem]!;

    private static async Task<JsonElement?> BodyAsync(HttpContext context)
    {
        try
        {
            using var document = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: context.RequestAborted).ConfigureAwait(false);
            return document.RootElement.ValueKind == JsonValueKind.Object ? document.RootElement.Clone() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>The request's filter (RFC 7644 §3.4.2.2), parsed; an error when it isn't a valid filter.</summary>
    private static Result<ScimFilter?> Filter(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return Result.Success<ScimFilter?>(null);
        }

        var parsed = ScimFilterParser.Parse(raw);
        return parsed.IsSuccess ? parsed.Value : parsed.Error;
    }

    private static JsonObject ListResponse<T>(ScimPage<T> page, Func<T, JsonObject> toJson) => new()
    {
        ["schemas"] = new JsonArray(ListSchema),
        ["totalResults"] = page.TotalResults,
        ["startIndex"] = page.StartIndex,
        ["itemsPerPage"] = page.Resources.Count,
        ["Resources"] = new JsonArray([.. page.Resources.Select(resource => (JsonNode)toJson(resource))]),
    };

    private static JsonObject Meta(string type, DateTimeOffset created, DateTimeOffset modified, int version, string location) => new()
    {
        ["resourceType"] = type,
        ["created"] = created.ToString("O", CultureInfo.InvariantCulture),
        ["lastModified"] = modified.ToString("O", CultureInfo.InvariantCulture),
        ["version"] = $"W/\"{version}\"",
        ["location"] = location,
    };

    private static string Location(HttpContext context, string resource, Guid id) =>
        $"{context.Request.Scheme}://{context.Request.Host}{context.Request.PathBase}/{Root}/{resource}/{id}";

    /// <summary>TryGetProperty that answers false, rather than throwing, when the element isn't an object.</summary>
    private static bool Has(JsonElement element, string property, out JsonElement value)
    {
        value = default;
        return element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out value);
    }

    private static string? Text(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && Has(element, property, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!.Trim()
            : null;

    private static bool? Bool(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.String when bool.TryParse(value.GetString(), out var parsed) => parsed,
        _ => null,
    };

    private static string? PrimaryEmail(JsonElement body)
    {
        if (!Has(body, "emails", out var emails) || emails.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var all = emails.EnumerateArray().Where(email => Text(email, "value") is not null).ToList();
        var primary = all.FirstOrDefault(email => Has(email, "primary", out var flag) && Bool(flag) == true);
        return Text(primary.ValueKind == JsonValueKind.Object ? primary : all.FirstOrDefault(), "value");
    }

    private static ScimResult Scim(int status, JsonObject body, string? location = null, int? version = null) => new(status, body, location, version);

    private static ScimResult NoContent(Result result) => result.IsSuccess ? new ScimResult(StatusCodes.Status204NoContent, null, null, null) : Error(result.Error);

    private static ScimResult NotFound() => Error(StatusCodes.Status404NotFound, ScimErrors.NotFound, "No such resource.");

    private static ScimResult Error(Error error) => error.Type switch
    {
        ErrorType.NotFound => Error(StatusCodes.Status404NotFound, null, error.Message),
        ErrorType.Conflict when error.Code == ScimErrors.PreconditionFailed => Error(StatusCodes.Status412PreconditionFailed, null, error.Message),
        ErrorType.Conflict when error.Code == ScimErrors.ConcurrentChange => Error(StatusCodes.Status409Conflict, null, error.Message),
        ErrorType.Conflict => Error(StatusCodes.Status409Conflict, ScimErrors.Uniqueness, error.Message),
        ErrorType.Unavailable => Error(StatusCodes.Status503ServiceUnavailable, null, error.Message),
        ErrorType.Validation => Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, string.Join(" ", error.Failures.Select(failure => failure.Message))),
        _ => Error(StatusCodes.Status400BadRequest, error.Code, error.Message),
    };

    internal static ScimResult Error(int status, string? scimType, string detail)
    {
        var body = new JsonObject
        {
            ["schemas"] = new JsonArray(ErrorSchema),
            ["status"] = status.ToString(CultureInfo.InvariantCulture),
            ["detail"] = detail,
        };
        if (scimType is not null)
        {
            body["scimType"] = scimType;
        }

        return new ScimResult(status, body, null, null);
    }

    private static JsonObject ServiceProviderConfig() => new()
    {
        ["schemas"] = new JsonArray("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"),
        ["patch"] = new JsonObject { ["supported"] = true },
        ["bulk"] = new JsonObject { ["supported"] = true, ["maxOperations"] = MaxBulkOperations, ["maxPayloadSize"] = MaxBulkPayloadBytes },
        ["filter"] = new JsonObject { ["supported"] = true, ["maxResults"] = 200 },
        ["changePassword"] = new JsonObject { ["supported"] = false },
        ["sort"] = new JsonObject { ["supported"] = true },
        ["etag"] = new JsonObject { ["supported"] = true },
        ["authenticationSchemes"] = new JsonArray(new JsonObject
        {
            ["type"] = "oauthbearertoken",
            ["name"] = "Bearer token",
            ["description"] = "A SCIM token issued by a tenant administrator.",
        }),
    };

    private static JsonObject ResourceTypes() => new()
    {
        ["schemas"] = new JsonArray(ListSchema),
        ["totalResults"] = 2,
        ["Resources"] = new JsonArray(
            new JsonObject { ["schemas"] = new JsonArray("urn:ietf:params:scim:schemas:core:2.0:ResourceType"), ["id"] = "User", ["name"] = "User", ["endpoint"] = "/Users", ["schema"] = UserSchema },
            new JsonObject { ["schemas"] = new JsonArray("urn:ietf:params:scim:schemas:core:2.0:ResourceType"), ["id"] = "Group", ["name"] = "Group", ["endpoint"] = "/Groups", ["schema"] = GroupSchema }),
    };


    [GeneratedRegex("^members\\[value eq \"([^\"]+)\"\\]$", RegexOptions.IgnoreCase)]
    private static partial Regex MemberFilter();

    /// <summary>Authenticates the tenant's SCIM token; answers a SCIM 401 otherwise.</summary>
    private sealed class ScimTokenFilter : IEndpointFilter
    {
        public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        {
            ArgumentNullException.ThrowIfNull(context);
            ArgumentNullException.ThrowIfNull(next);

            var http = context.HttpContext;
            var header = http.Request.Headers.Authorization.ToString();
            var secret = header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header[7..].Trim() : null;

            // Rate limited per token (its hash) before it is looked up: one tenant's provisioning can't swamp the server.
            var limits = http.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptions<Abstractions.RateLimiting.RateLimitOptions>>().Value;
            if (limits.Enabled && !http.RequestServices.GetRequiredService<Abstractions.RateLimiting.RequestRateLimiter>().TryAcquire(
                    limits.ScimPerToken,
                    Abstractions.RateLimiting.RateLimitPartitions.For("scim-token", Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(secret ?? string.Empty)))),
                    out var wait))
            {
                http.Response.Headers.RetryAfter = Math.Max(1, (int)Math.Ceiling(wait.TotalSeconds)).ToString(System.Globalization.CultureInfo.InvariantCulture);
                return Error(StatusCodes.Status429TooManyRequests, null, "Too many requests. Try again later.");
            }

            var tenant = await http.RequestServices.GetRequiredService<ScimTokenAuthenticator>().AuthenticateAsync(secret, http.RequestAborted).ConfigureAwait(false);
            if (tenant is null)
            {
                http.Response.Headers.WWWAuthenticate = "Bearer";
                return Error(StatusCodes.Status401Unauthorized, null, "A valid SCIM token is required.");
            }

            http.Items[TenantItem] = tenant.Value;
            return await next(context).ConfigureAwait(false);
        }
    }

    /// <summary>A SCIM answer: the body (with the <c>application/scim+json</c> media type), and the resource's ETag when it has one.</summary>
    internal sealed class ScimResult(int status, JsonObject? body, string? location, int? version) : IResult
    {
        public int Status { get; } = status;

        public JsonObject? Body { get; } = body;

        public string? Location { get; } = location;

        public int? Version { get; } = version;

        public async Task ExecuteAsync(HttpContext httpContext)
        {
            ArgumentNullException.ThrowIfNull(httpContext);
            httpContext.Response.StatusCode = Status;
            if (Location is not null)
            {
                httpContext.Response.Headers.Location = Location;
            }

            if (Version is { } current)
            {
                httpContext.Response.Headers.ETag = ETag(current);
            }

            if (Body is not null)
            {
                httpContext.Response.ContentType = ContentType;
                await httpContext.Response.WriteAsync(Body.ToJsonString(), httpContext.RequestAborted).ConfigureAwait(false);
            }
        }
    }
}

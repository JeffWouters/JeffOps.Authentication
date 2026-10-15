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

namespace JeffOps.Authentication.Enterprise.Endpoints;

/// <summary>
/// SCIM 2.0 (RFC 7643/7644) for tenants' identity providers: <c>Users</c> and <c>Groups</c> with create, replace, patch,
/// delete, get and list (filters: <c>userName</c>/<c>externalId</c>/<c>displayName</c> <c>eq</c>), plus the discovery
/// resources. Authenticated with a tenant's SCIM token; everything happens in that tenant.
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
    private const string TenantItem = "JeffOps.Scim.Tenant";

    public static IEndpointRouteBuilder MapJeffOpsScim(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var scim = endpoints.MapGroup(Root).WithTags("SCIM").AllowAnonymous().DisableAntiforgery().AddEndpointFilter<ScimTokenFilter>();

        scim.MapGet("ServiceProviderConfig", () => Scim(StatusCodes.Status200OK, ServiceProviderConfig()));
        scim.MapGet("ResourceTypes", () => Scim(StatusCodes.Status200OK, ResourceTypes()));

        scim.MapGet("Users", ListUsersAsync);
        scim.MapGet("Users/{id}", async (string id, HttpContext context, IQueryHandler<GetScimUserQuery, ScimUserView> handler) =>
            !Guid.TryParse(id, out var userId) ? NotFound()
            : UserResult(await handler.HandleAsync(new GetScimUserQuery(Tenant(context), userId), context.RequestAborted).ConfigureAwait(false), context));
        scim.MapPost("Users", CreateUserAsync);
        scim.MapPut("Users/{id}", ReplaceUserAsync);
        scim.MapPatch("Users/{id}", PatchUserAsync);
        scim.MapDelete("Users/{id}", async (string id, HttpContext context, ICommandHandler<DeleteScimUserCommand> handler) =>
            !Guid.TryParse(id, out var userId) ? NotFound()
            : NoContent(await handler.HandleAsync(new DeleteScimUserCommand(Tenant(context), userId), context.RequestAborted).ConfigureAwait(false)));

        scim.MapGet("Groups", ListGroupsAsync);
        scim.MapGet("Groups/{id}", async (string id, HttpContext context, IQueryHandler<GetScimGroupQuery, ScimGroupView> handler) =>
            !Guid.TryParse(id, out var groupId) ? NotFound()
            : GroupResult(await handler.HandleAsync(new GetScimGroupQuery(Tenant(context), groupId), context.RequestAborted).ConfigureAwait(false), context));
        scim.MapPost("Groups", CreateGroupAsync);
        scim.MapPut("Groups/{id}", ReplaceGroupAsync);
        scim.MapPatch("Groups/{id}", PatchGroupAsync);
        scim.MapDelete("Groups/{id}", async (string id, HttpContext context, ICommandHandler<DeleteScimGroupCommand> handler) =>
            !Guid.TryParse(id, out var groupId) ? NotFound()
            : NoContent(await handler.HandleAsync(new DeleteScimGroupCommand(Tenant(context), groupId), context.RequestAborted).ConfigureAwait(false)));

        return endpoints;
    }

    // ---- Users ---------------------------------------------------------------------------------------------------------

    private static async Task<IResult> ListUsersAsync(HttpContext context, IQueryHandler<ListScimUsersQuery, ScimPage<ScimUserView>> handler)
    {
        if (!TryFilter(context, out var filter))
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidFilter, "Only 'attribute eq \"value\"' filters are supported.");
        }

        var (startIndex, count) = Paging(context);
        var result = await handler.HandleAsync(new ListScimUsersQuery(Tenant(context), filter, startIndex, count), context.RequestAborted).ConfigureAwait(false);
        return result.IsSuccess ? Scim(StatusCodes.Status200OK, ListResponse(result.Value, user => UserJson(user, context))) : Error(result.Error);
    }

    private static async Task<IResult> CreateUserAsync(HttpContext context, ICommandHandler<CreateScimUserCommand, ScimUserView> handler)
    {
        if (await BodyAsync(context).ConfigureAwait(false) is not { } body || ParseUser(body) is not { } data)
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "A user needs a userName.");
        }

        var result = await handler.HandleAsync(new CreateScimUserCommand(Tenant(context), data), context.RequestAborted).ConfigureAwait(false);
        return result.IsSuccess ? Scim(StatusCodes.Status201Created, UserJson(result.Value, context), Location(context, "Users", result.Value.Id)) : Error(result.Error);
    }

    private static async Task<IResult> ReplaceUserAsync(string id, HttpContext context, ICommandHandler<UpdateScimUserCommand, ScimUserView> handler)
    {
        if (!Guid.TryParse(id, out var userId))
        {
            return NotFound();
        }

        if (await BodyAsync(context).ConfigureAwait(false) is not { } body || ParseUser(body) is not { } data)
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "A user needs a userName.");
        }

        return UserResult(await handler.HandleAsync(new UpdateScimUserCommand(Tenant(context), userId, _ => data), context.RequestAborted).ConfigureAwait(false), context);
    }

    private static async Task<IResult> PatchUserAsync(string id, HttpContext context, ICommandHandler<UpdateScimUserCommand, ScimUserView> handler)
    {
        if (!Guid.TryParse(id, out var userId))
        {
            return NotFound();
        }

        if (await BodyAsync(context).ConfigureAwait(false) is not { } body || !body.TryGetProperty("Operations", out var operations) || operations.ValueKind != JsonValueKind.Array)
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "A PATCH needs Operations.");
        }

        var ops = operations.Clone();
        return UserResult(await handler.HandleAsync(new UpdateScimUserCommand(Tenant(context), userId, current => ApplyUserPatch(current, ops)), context.RequestAborted).ConfigureAwait(false), context);
    }

    private static ScimUserData? ParseUser(JsonElement body)
    {
        if (Text(body, "userName") is not { } userName)
        {
            return null;
        }

        var name = body.TryGetProperty("name", out var nameElement) && nameElement.ValueKind == JsonValueKind.Object ? nameElement : default;
        return new ScimUserData(
            userName,
            Text(body, "externalId"),
            name.ValueKind == JsonValueKind.Object ? Text(name, "givenName") : null,
            name.ValueKind == JsonValueKind.Object ? Text(name, "familyName") : null,
            Text(body, "displayName"),
            PrimaryEmail(body),
            !body.TryGetProperty("active", out var active) || Bool(active) != false);
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
            var hasValue = operation.TryGetProperty("value", out var value);

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

    private static IResult UserResult(Result<ScimUserView> result, HttpContext context) =>
        result.IsSuccess ? Scim(StatusCodes.Status200OK, UserJson(result.Value, context)) : Error(result.Error);

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

    private static async Task<IResult> ListGroupsAsync(HttpContext context, IQueryHandler<ListScimGroupsQuery, ScimPage<ScimGroupView>> handler)
    {
        if (!TryFilter(context, out var filter))
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidFilter, "Only 'attribute eq \"value\"' filters are supported.");
        }

        var (startIndex, count) = Paging(context);
        var excludeMembers = string.Equals(context.Request.Query["excludedAttributes"], "members", StringComparison.OrdinalIgnoreCase);
        var result = await handler.HandleAsync(new ListScimGroupsQuery(Tenant(context), filter, startIndex, count), context.RequestAborted).ConfigureAwait(false);
        return result.IsSuccess ? Scim(StatusCodes.Status200OK, ListResponse(result.Value, group => GroupJson(group, context, excludeMembers))) : Error(result.Error);
    }

    private static async Task<IResult> CreateGroupAsync(HttpContext context, ICommandHandler<CreateScimGroupCommand, ScimGroupView> handler)
    {
        if (await BodyAsync(context).ConfigureAwait(false) is not { } body || Text(body, "displayName") is not { } displayName)
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "A group needs a displayName.");
        }

        if (!TryMembers(body.TryGetProperty("members", out var members) ? members : default, out var memberIds))
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "Member values must be user ids.");
        }

        var result = await handler.HandleAsync(new CreateScimGroupCommand(Tenant(context), displayName, Text(body, "externalId"), memberIds), context.RequestAborted).ConfigureAwait(false);
        return result.IsSuccess ? Scim(StatusCodes.Status201Created, GroupJson(result.Value, context), Location(context, "Groups", result.Value.Id)) : Error(result.Error);
    }

    private static async Task<IResult> ReplaceGroupAsync(string id, HttpContext context, ICommandHandler<UpdateScimGroupCommand, ScimGroupView> handler)
    {
        if (!Guid.TryParse(id, out var groupId))
        {
            return NotFound();
        }

        if (await BodyAsync(context).ConfigureAwait(false) is not { } body || Text(body, "displayName") is not { } displayName
            || !TryMembers(body.TryGetProperty("members", out var members) ? members : default, out var memberIds))
        {
            return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "A group needs a displayName and user ids as members.");
        }

        var change = new ScimGroupChange(displayName, Text(body, "externalId"), ReplaceMembers: memberIds);
        return GroupResult(await handler.HandleAsync(new UpdateScimGroupCommand(Tenant(context), groupId, change), context.RequestAborted).ConfigureAwait(false), context);
    }

    private static async Task<IResult> PatchGroupAsync(string id, HttpContext context, ICommandHandler<UpdateScimGroupCommand, ScimGroupView> handler)
    {
        if (!Guid.TryParse(id, out var groupId))
        {
            return NotFound();
        }

        if (await BodyAsync(context).ConfigureAwait(false) is not { } body || !body.TryGetProperty("Operations", out var operations) || operations.ValueKind != JsonValueKind.Array)
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
            var value = operation.TryGetProperty("value", out var v) ? v : default;

            if (path is null && value.ValueKind == JsonValueKind.Object)
            {
                displayName = Text(value, "displayName") ?? displayName;
                externalId = Text(value, "externalId") ?? externalId;
                if (value.TryGetProperty("members", out var objectMembers))
                {
                    if (!TryMembers(objectMembers, out var ids))
                    {
                        return Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, "Member values must be user ids.");
                    }

                    (op == "add" ? add : null)?.AddRange(ids);
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
        return GroupResult(await handler.HandleAsync(new UpdateScimGroupCommand(Tenant(context), groupId, change), context.RequestAborted).ConfigureAwait(false), context);
    }

    private static IResult GroupResult(Result<ScimGroupView> result, HttpContext context) =>
        result.IsSuccess ? Scim(StatusCodes.Status200OK, GroupJson(result.Value, context)) : Error(result.Error);

    private static JsonObject GroupJson(ScimGroupView group, HttpContext context, bool excludeMembers = false)
    {
        var json = new JsonObject
        {
            ["schemas"] = new JsonArray(GroupSchema),
            ["id"] = group.Id.ToString(),
            ["externalId"] = group.ExternalId,
            ["displayName"] = group.DisplayName,
            ["meta"] = Meta("Group", group.Created, group.LastModified, group.Version, Location(context, "Groups", group.Id)),
        };
        if (!excludeMembers)
        {
            json["members"] = new JsonArray([.. group.Members.Select(member => (JsonNode)new JsonObject { ["value"] = member.ToString(), ["$ref"] = Location(context, "Users", member) })]);
        }

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

    private static bool TryFilter(HttpContext context, out ScimFilter? filter)
    {
        filter = null;
        var raw = context.Request.Query["filter"].ToString();
        if (string.IsNullOrWhiteSpace(raw))
        {
            return true;
        }

        if (EqualityFilter().Match(raw.Trim()) is not { Success: true } match)
        {
            return false;
        }

        filter = new ScimFilter(match.Groups[1].Value, match.Groups[2].Value.Replace("\\\"", "\"", StringComparison.Ordinal));
        return true;
    }

    private static (int StartIndex, int Count) Paging(HttpContext context) =>
        (int.TryParse(context.Request.Query["startIndex"], NumberStyles.Integer, CultureInfo.InvariantCulture, out var start) ? start : 1,
         int.TryParse(context.Request.Query["count"], NumberStyles.Integer, CultureInfo.InvariantCulture, out var count) ? count : 100);

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

    private static string? Text(JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(value.GetString())
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
        if (!body.TryGetProperty("emails", out var emails) || emails.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        var all = emails.EnumerateArray().Where(email => Text(email, "value") is not null).ToList();
        var primary = all.FirstOrDefault(email => email.TryGetProperty("primary", out var flag) && Bool(flag) == true);
        return Text(primary.ValueKind == JsonValueKind.Object ? primary : all.FirstOrDefault(), "value");
    }

    private static IResult Scim(int status, JsonObject body, string? location = null) => new ScimResult(status, body, location);

    private static IResult NoContent(Result result) => result.IsSuccess ? TypedResults.NoContent() : Error(result.Error);

    private static IResult NotFound() => Error(StatusCodes.Status404NotFound, ScimErrors.NotFound, "No such resource.");

    private static IResult Error(Error error) => error.Type switch
    {
        ErrorType.NotFound => Error(StatusCodes.Status404NotFound, null, error.Message),
        ErrorType.Conflict => Error(StatusCodes.Status409Conflict, ScimErrors.Uniqueness, error.Message),
        ErrorType.Unavailable => Error(StatusCodes.Status503ServiceUnavailable, null, error.Message),
        ErrorType.Validation => Error(StatusCodes.Status400BadRequest, ScimErrors.InvalidValue, string.Join(" ", error.Failures.Select(failure => failure.Message))),
        _ => Error(StatusCodes.Status400BadRequest, error.Code, error.Message),
    };

    internal static IResult Error(int status, string? scimType, string detail)
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

        return new ScimResult(status, body, null);
    }

    private static JsonObject ServiceProviderConfig() => new()
    {
        ["schemas"] = new JsonArray("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"),
        ["patch"] = new JsonObject { ["supported"] = true },
        ["bulk"] = new JsonObject { ["supported"] = false, ["maxOperations"] = 0, ["maxPayloadSize"] = 0 },
        ["filter"] = new JsonObject { ["supported"] = true, ["maxResults"] = 200 },
        ["changePassword"] = new JsonObject { ["supported"] = false },
        ["sort"] = new JsonObject { ["supported"] = false },
        ["etag"] = new JsonObject { ["supported"] = false },
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

    [GeneratedRegex("^(userName|externalId|displayName) eq \"((?:[^\"\\\\]|\\\\.)*)\"$", RegexOptions.IgnoreCase)]
    private static partial Regex EqualityFilter();

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

    /// <summary>Writes a SCIM body with the <c>application/scim+json</c> media type.</summary>
    private sealed class ScimResult(int status, JsonObject body, string? location) : IResult
    {
        public async Task ExecuteAsync(HttpContext httpContext)
        {
            ArgumentNullException.ThrowIfNull(httpContext);
            httpContext.Response.StatusCode = status;
            httpContext.Response.ContentType = ContentType;
            if (location is not null)
            {
                httpContext.Response.Headers.Location = location;
            }

            await httpContext.Response.WriteAsync(body.ToJsonString(), httpContext.RequestAborted).ConfigureAwait(false);
        }
    }
}

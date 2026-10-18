using System.Globalization;
using System.Linq.Expressions;
using System.Reflection;
using System.Text.Json;
using JeffOps.Authentication.Enterprise.Domain;
using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.Enterprise.Application;

/// <summary>
/// A SCIM filter (RFC 7644 §3.4.2.2): comparisons (<c>eq ne co sw ew gt ge lt le</c>), presence (<c>pr</c>), <c>and</c>,
/// <c>or</c>, <c>not</c>, grouping, and value paths (<c>members[value eq "…"]</c>). Attribute names are as written, without
/// their schema URN.
/// </summary>
public abstract record ScimFilter
{
    /// <summary>The filter <c>{attribute} eq "{value}"</c>.</summary>
    public static ScimFilter Eq(string attribute, string value) => new ScimComparison(attribute, "eq", value);
}

/// <summary><paramref name="Attribute"/> <paramref name="Operator"/> <paramref name="Value"/>: a string, bool, number or null; none for <c>pr</c>.</summary>
public sealed record ScimComparison(string Attribute, string Operator, object? Value) : ScimFilter;

public sealed record ScimAnd(ScimFilter Left, ScimFilter Right) : ScimFilter;

public sealed record ScimOr(ScimFilter Left, ScimFilter Right) : ScimFilter;

public sealed record ScimNot(ScimFilter Inner) : ScimFilter;

/// <summary><c>{Attribute}[{Inner}]</c>: some value of a multi-valued attribute matches <paramref name="Inner"/>.</summary>
public sealed record ScimValuePath(string Attribute, ScimFilter Inner) : ScimFilter;

/// <summary>
/// Parses SCIM filters. Bounded, since they come from outside: at most 2,048 characters, 32 levels of nesting and 100
/// comparisons.
/// </summary>
public static class ScimFilterParser
{
    private const int MaxLength = 2048;
    private const int MaxDepth = 32;
    private const int MaxComparisons = 100;
    private static readonly string[] Operators = ["eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"];

    public static Result<ScimFilter> Parse(string filter)
    {
        ArgumentNullException.ThrowIfNull(filter);
        if (filter.Length > MaxLength)
        {
            return Invalid($"A filter is at most {MaxLength} characters.");
        }

        try
        {
            var parser = new Parser(Tokenize(filter));
            var parsed = parser.Or(0);
            return parser.AtEnd ? parsed : Invalid($"Unexpected '{parser.Peek}'.");
        }
        catch (FormatException exception)
        {
            return Invalid(exception.Message);
        }
    }

    private static Error Invalid(string message) => Error.Failure(ScimErrors.InvalidFilter, message);

    private static List<string> Tokenize(string filter)
    {
        var tokens = new List<string>();
        var index = 0;
        while (index < filter.Length)
        {
            var character = filter[index];
            if (char.IsWhiteSpace(character))
            {
                index++;
            }
            else if (character is '(' or ')' or '[' or ']')
            {
                tokens.Add(character.ToString());
                index++;
            }
            else if (character == '"')
            {
                var end = index + 1;
                while (end < filter.Length && filter[end] != '"')
                {
                    end += filter[end] == '\\' ? 2 : 1;
                }

                if (end >= filter.Length)
                {
                    throw new FormatException("A string isn't closed.");
                }

                tokens.Add(filter[index..(end + 1)]);
                index = end + 1;
            }
            else
            {
                var end = index;
                while (end < filter.Length && !char.IsWhiteSpace(filter[end]) && filter[end] is not ('(' or ')' or '[' or ']' or '"'))
                {
                    end++;
                }

                tokens.Add(filter[index..end]);
                index = end;
            }
        }

        return tokens;
    }

    private sealed class Parser(List<string> tokens)
    {
        private int _position;
        private int _comparisons;

        public bool AtEnd => _position >= tokens.Count;

        public string Peek => AtEnd ? "end of filter" : tokens[_position];

        public ScimFilter Or(int depth)
        {
            var left = And(depth);
            while (Accept("or"))
            {
                left = new ScimOr(left, And(depth));
            }

            return left;
        }

        private ScimFilter And(int depth)
        {
            var left = Unary(depth);
            while (Accept("and"))
            {
                left = new ScimAnd(left, Unary(depth));
            }

            return left;
        }

        private ScimFilter Unary(int depth)
        {
            if (depth > MaxDepth)
            {
                throw new FormatException("The filter is nested too deeply.");
            }

            if (Accept("not"))
            {
                Expect("(");
                var inner = Or(depth + 1);
                Expect(")");
                return new ScimNot(inner);
            }

            if (Accept("("))
            {
                var inner = Or(depth + 1);
                Expect(")");
                return inner;
            }

            var attribute = Attribute(Next("an attribute"));
            if (Accept("["))
            {
                var inner = Or(depth + 1);
                Expect("]");
                return new ScimValuePath(attribute, inner);
            }

            if (++_comparisons > MaxComparisons)
            {
                throw new FormatException($"A filter has at most {MaxComparisons} comparisons.");
            }

            var op = Next("an operator").ToLowerInvariant();
            if (op == "pr")
            {
                return new ScimComparison(attribute, op, null);
            }

            if (!Operators.Contains(op))
            {
                throw new FormatException($"'{op}' isn't a filter operator.");
            }

            return new ScimComparison(attribute, op, Value(Next("a value")));
        }

        private static string Attribute(string token)
        {
            if (token is "(" or ")" or "[" or "]" || token.StartsWith('"'))
            {
                throw new FormatException($"Expected an attribute, found '{token}'.");
            }

            // A full name (urn:…:User:name.givenName) is the attribute after its schema.
            return token.StartsWith("urn:", StringComparison.OrdinalIgnoreCase) ? token[(token.LastIndexOf(':') + 1)..] : token;
        }

        private static object? Value(string token)
        {
            if (token.StartsWith('"'))
            {
                try
                {
                    return JsonSerializer.Deserialize<string>(token);
                }
                catch (JsonException)
                {
                    throw new FormatException("A string has an invalid escape.");
                }
            }

            return token.ToLowerInvariant() switch
            {
                "true" => true,
                "false" => false,
                "null" => null,
                _ when decimal.TryParse(token, NumberStyles.Float, CultureInfo.InvariantCulture, out var number) => number,
                _ => throw new FormatException($"'{token}' isn't a value: quote strings."),
            };
        }

        private bool Accept(string keyword)
        {
            if (!AtEnd && string.Equals(tokens[_position], keyword, StringComparison.OrdinalIgnoreCase))
            {
                _position++;
                return true;
            }

            return false;
        }

        private void Expect(string token)
        {
            if (!Accept(token))
            {
                throw new FormatException($"Expected '{token}', found '{Peek}'.");
            }
        }

        private string Next(string what) => AtEnd ? throw new FormatException($"Expected {what} at the end of the filter.") : tokens[_position++];
    }
}

/// <summary>
/// Turns filters into database predicates for users and groups. Strings compare case-insensitively except
/// <c>externalId</c> (RFC 7643 §3.1); <c>ne</c> matches resources without the attribute; timestamps compare as instants.
/// </summary>
public static class ScimFilters
{
    /// <summary>A predicate for users; with <paramref name="lenient"/> (searches across resource types) an attribute users don't have matches nothing.</summary>
    public static Result<Expression<Func<ScimUser, bool>>> ForUsers(ScimFilter filter, bool lenient = false) => Translate<ScimUser>(filter, UserAttribute, lenient);

    /// <summary>A predicate for groups; see <see cref="ForUsers"/>.</summary>
    public static Result<Expression<Func<ScimGroup, bool>>> ForGroups(ScimFilter filter, bool lenient = false) => Translate<ScimGroup>(filter, GroupAttribute, lenient);

    private enum Kind
    {
        Text,

        /// <summary>Case-insensitive text stored lower-cased: compared as it is, so an index on it can be used.</summary>
        NormalizedText,
        CaseExactText,
        Boolean,
        Instant,
        Id,
    }

    private sealed record Attribute(Kind Kind, Func<Expression, Expression> Access);

    private static Attribute? UserAttribute(string name) => name.ToLowerInvariant() switch
    {
        "id" => new(Kind.Id, user => Expression.Property(user, nameof(ScimUser.AccountId))),
        "username" => new(Kind.NormalizedText, user => Expression.Property(user, nameof(ScimUser.NormalizedUserName))),
        "externalid" => new(Kind.CaseExactText, user => Expression.Property(user, nameof(ScimUser.ExternalId))),
        "displayname" => new(Kind.Text, user => Expression.Property(user, nameof(ScimUser.DisplayName))),
        "name.givenname" => new(Kind.Text, user => Expression.Property(user, nameof(ScimUser.GivenName))),
        "name.familyname" => new(Kind.Text, user => Expression.Property(user, nameof(ScimUser.FamilyName))),
        "active" => new(Kind.Boolean, user => Expression.Property(user, nameof(ScimUser.Active))),
        "meta.created" => new(Kind.Instant, user => Expression.Property(user, nameof(ScimUser.Created))),
        "meta.lastmodified" => new(Kind.Instant, user => Expression.Property(user, nameof(ScimUser.LastModified))),
        _ => null,
    };

    private static Attribute? GroupAttribute(string name) => name.ToLowerInvariant() switch
    {
        "id" => new(Kind.Id, group => Expression.Property(group, nameof(ScimGroup.Id))),
        "displayname" => new(Kind.NormalizedText, group => Expression.Property(group, nameof(ScimGroup.NormalizedDisplayName))),
        "externalid" => new(Kind.CaseExactText, group => Expression.Property(group, nameof(ScimGroup.ExternalId))),
        "meta.created" => new(Kind.Instant, group => Expression.Property(group, nameof(ScimGroup.Created))),
        "meta.lastmodified" => new(Kind.Instant, group => Expression.Property(group, nameof(ScimGroup.LastModified))),
        _ => null,
    };

    private static Attribute? MemberAttribute(string name) => name.ToLowerInvariant() switch
    {
        "value" => new(Kind.Id, member => Expression.Property(member, nameof(ScimGroupMember.AccountId))),
        _ => null,
    };

    private static Result<Expression<Func<T, bool>>> Translate<T>(ScimFilter filter, Func<string, Attribute?> attributes, bool lenient)
    {
        ArgumentNullException.ThrowIfNull(filter);
        var parameter = Expression.Parameter(typeof(T), "resource");
        try
        {
            return Expression.Lambda<Func<T, bool>>(Body(filter, parameter, attributes, lenient), parameter);
        }
        catch (FormatException exception)
        {
            return Error.Failure(ScimErrors.InvalidFilter, exception.Message);
        }
    }

    private static Expression Body(ScimFilter filter, Expression resource, Func<string, Attribute?> attributes, bool lenient) => filter switch
    {
        ScimAnd and => Expression.AndAlso(Body(and.Left, resource, attributes, lenient), Body(and.Right, resource, attributes, lenient)),
        ScimOr or => Expression.OrElse(Body(or.Left, resource, attributes, lenient), Body(or.Right, resource, attributes, lenient)),
        ScimNot not => Expression.Not(Body(not.Inner, resource, attributes, lenient)),
        ScimValuePath path => ValuePath(path, resource, attributes, lenient),
        ScimComparison { Operator: "pr" } comparison when comparison.Attribute.Equals("members", StringComparison.OrdinalIgnoreCase) && resource.Type == typeof(ScimGroup) =>
            Expression.Call(AnyMember, Expression.Property(resource, nameof(ScimGroup.Members))),
        ScimComparison comparison when comparison.Attribute.Equals("members.value", StringComparison.OrdinalIgnoreCase) && resource.Type == typeof(ScimGroup) =>
            ValuePath(new ScimValuePath("members", comparison with { Attribute = "value" }), resource, attributes, lenient),
        ScimComparison comparison => attributes(comparison.Attribute) is { } attribute
            ? Compare(attribute.Access(resource), attribute.Kind, comparison.Operator, comparison.Value, comparison.Attribute)
            : lenient ? Expression.Constant(false) : throw new FormatException($"Can't filter by '{comparison.Attribute}'."),
        _ => throw new FormatException("Unsupported filter."),
    };

    /// <summary><c>members[…]</c> and <c>members pr</c> on groups: some member matches.</summary>
    private static Expression ValuePath(ScimValuePath path, Expression resource, Func<string, Attribute?> attributes, bool lenient)
    {
        if (resource.Type != typeof(ScimGroup) || !path.Attribute.Equals("members", StringComparison.OrdinalIgnoreCase))
        {
            return lenient ? Expression.Constant(false) : throw new FormatException($"Can't filter by '{path.Attribute}[…]'.");
        }

        var member = Expression.Parameter(typeof(ScimGroupMember), "member");
        var inner = Expression.Lambda<Func<ScimGroupMember, bool>>(Body(path.Inner, member, MemberAttribute, lenient), member);
        return Expression.Call(Any, Expression.Property(resource, nameof(ScimGroup.Members)), inner);
    }

    private static Expression Compare(Expression value, Kind kind, string op, object? literal, string name)
    {
        if (op == "pr")
        {
            return kind is Kind.Text or Kind.NormalizedText or Kind.CaseExactText
                ? Expression.AndAlso(Expression.NotEqual(value, Null), Expression.NotEqual(value, Parameter(string.Empty)))
                : Expression.Constant(true);
        }

        switch (kind)
        {
            case Kind.Text or Kind.NormalizedText or Kind.CaseExactText:
                if (literal is null && op is "eq" or "ne")
                {
                    return op == "eq" ? Expression.Equal(value, Null) : Expression.NotEqual(value, Null);
                }

                if (literal is not string text)
                {
                    throw new FormatException($"'{name}' is compared with a string.");
                }

                var compared = kind == Kind.Text ? Expression.Call(value, ToLower) : value;
                var against = Parameter(kind switch
                {
                    Kind.Text => text.ToLowerInvariant(),
                    Kind.NormalizedText => ScimUser.Normalize(text),
                    _ => text,
                });
                var present = Expression.NotEqual(value, Null);
                return op switch
                {
                    "eq" => Expression.AndAlso(present, Expression.Equal(compared, against)),
                    "ne" => Expression.OrElse(Expression.Equal(value, Null), Expression.NotEqual(compared, against)),
                    "co" => Expression.AndAlso(present, Expression.Call(compared, Contains, against)),
                    "sw" => Expression.AndAlso(present, Expression.Call(compared, StartsWith, against)),
                    "ew" => Expression.AndAlso(present, Expression.Call(compared, EndsWith, against)),
                    _ => Expression.AndAlso(present, Ordered(Expression.Call(CompareStrings, compared, against), Expression.Constant(0), op)),
                };

            case Kind.Boolean:
                if (literal is not bool flag || op is not ("eq" or "ne"))
                {
                    throw new FormatException($"'{name}' is compared with true or false, by eq or ne.");
                }

                return op == "eq" ? Expression.Equal(value, Parameter(flag)) : Expression.NotEqual(value, Parameter(flag));

            case Kind.Id:
                if (op is not ("eq" or "ne"))
                {
                    throw new FormatException($"'{name}' is compared by eq or ne.");
                }

                // An id that isn't one of ours matches nothing (and everything for ne).
                if (literal is not string raw || !Guid.TryParse(raw, out var id))
                {
                    return Expression.Constant(op == "ne");
                }

                return op == "eq" ? Expression.Equal(value, Parameter(id)) : Expression.NotEqual(value, Parameter(id));

            case Kind.Instant:
                if (literal is not string when || !DateTimeOffset.TryParse(when, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var instant))
                {
                    throw new FormatException($"'{name}' is compared with a date and time (ISO 8601).");
                }

                if (op is "co" or "sw" or "ew")
                {
                    throw new FormatException($"'{name}' can't be compared by {op}.");
                }

                return op switch
                {
                    "eq" => Expression.Equal(value, Parameter(instant)),
                    "ne" => Expression.NotEqual(value, Parameter(instant)),
                    _ => Ordered(value, Parameter(instant), op),
                };

            default:
                throw new FormatException("Unsupported attribute.");
        }
    }

    private static BinaryExpression Ordered(Expression left, Expression right, string op) => op switch
    {
        "gt" => Expression.GreaterThan(left, right),
        "ge" => Expression.GreaterThanOrEqual(left, right),
        "lt" => Expression.LessThan(left, right),
        "le" => Expression.LessThanOrEqual(left, right),
        _ => throw new FormatException($"'{op}' isn't a filter operator."),
    };

    /// <summary>A captured value, so the database sees a parameter rather than SQL text built from the filter.</summary>
    private static MemberExpression Parameter<TValue>(TValue value) => Expression.Property(Expression.Constant(new Captured<TValue>(value)), nameof(Captured<TValue>.Value));

    private sealed class Captured<TValue>(TValue value)
    {
        public TValue Value { get; } = value;
    }

    private static readonly ConstantExpression Null = Expression.Constant(null, typeof(string));
    private static readonly MethodInfo ToLower = typeof(string).GetMethod(nameof(string.ToLower), Type.EmptyTypes)!;
    private static readonly MethodInfo Contains = typeof(string).GetMethod(nameof(string.Contains), [typeof(string)])!;
    private static readonly MethodInfo StartsWith = typeof(string).GetMethod(nameof(string.StartsWith), [typeof(string)])!;
    private static readonly MethodInfo EndsWith = typeof(string).GetMethod(nameof(string.EndsWith), [typeof(string)])!;
    private static readonly MethodInfo CompareStrings = typeof(string).GetMethod(nameof(string.Compare), [typeof(string), typeof(string)])!;
    private static readonly MethodInfo AnyMember = typeof(Enumerable).GetMethods()
        .Single(method => method.Name == nameof(Enumerable.Any) && method.GetParameters().Length == 1)
        .MakeGenericMethod(typeof(ScimGroupMember));
    private static readonly MethodInfo Any = typeof(Enumerable).GetMethods()
        .Single(method => method.Name == nameof(Enumerable.Any) && method.GetParameters().Length == 2)
        .MakeGenericMethod(typeof(ScimGroupMember));
}

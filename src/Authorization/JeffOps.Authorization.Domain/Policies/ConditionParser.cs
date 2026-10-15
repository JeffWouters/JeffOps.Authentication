using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace JeffOps.Authorization.Domain.Policies;

/// <summary>
/// Parses the JSON condition grammar into a <see cref="Condition"/>. Each node is a one-key object:
/// <code>
/// { }                                                 always true
/// { "true": true }                                    always true
/// { "and": [ node, ... ] }                            all hold
/// { "or":  [ node, ... ] }                            any holds
/// { "not": node }                                     negation
/// { "eq"|"ne"|"lt"|"le"|"gt"|"ge": [ left, right ] }  comparison
/// { "in": [ value, [ literal, ... ] ] }               value is one of the literals
/// { "contains": [ arrayRef, value ] }                 array attribute contains value
/// </code>
/// A string operand that is <c>action</c> or starts with <c>subject.</c>, <c>resource.</c> or <c>environment.</c> is an
/// attribute reference; anything else is a literal.
/// </summary>
public static class ConditionParser
{
    private static readonly HashSet<string> Comparisons = new(StringComparer.Ordinal) { "eq", "ne", "lt", "le", "gt", "ge" };

    /// <summary>Parses <paramref name="conditionJson"/>; blank means "always".</summary>
    /// <exception cref="FormatException">The JSON is malformed or uses an unknown operator.</exception>
    public static Condition Parse(string? conditionJson)
    {
        if (string.IsNullOrWhiteSpace(conditionJson))
        {
            return Condition.Always;
        }

        try
        {
            using var document = JsonDocument.Parse(conditionJson);
            return ParseNode(document.RootElement);
        }
        catch (JsonException exception)
        {
            throw new FormatException($"Condition is not valid JSON: {exception.Message}", exception);
        }
    }

    public static bool TryParse(string? conditionJson, [NotNullWhen(true)] out Condition? condition, [NotNullWhen(false)] out string? error)
    {
        try
        {
            condition = Parse(conditionJson);
            error = null;
            return true;
        }
        catch (FormatException exception)
        {
            condition = null;
            error = exception.Message;
            return false;
        }
    }

    private static Condition ParseNode(JsonElement node)
    {
        if (node.ValueKind != JsonValueKind.Object)
        {
            throw new FormatException($"A condition node must be an object, not {node.ValueKind}.");
        }

        using var properties = node.EnumerateObject();
        if (!properties.MoveNext())
        {
            return Condition.Always;
        }

        var property = properties.Current;
        if (properties.MoveNext())
        {
            throw new FormatException("A condition node must have exactly one operator.");
        }

        var op = property.Name.ToLowerInvariant();
        var value = property.Value;

        return op switch
        {
            "true" => Condition.Always,
            "and" => new Condition.All(Array(value, op).Select(ParseNode).ToList()),
            "or" => new Condition.Any(Array(value, op).Select(ParseNode).ToList()),
            "not" => new Condition.Not(ParseNode(value)),
            _ when Comparisons.Contains(op) => Pair(value, op, (left, right) => new Condition.Comparison(op, Operand.From(left), Operand.From(right))),
            "in" => Pair(value, op, (left, right) =>
                right.ValueKind == JsonValueKind.Array
                    ? new Condition.In(Operand.From(left), right.EnumerateArray().Select(Operand.From).ToList())
                    : throw new FormatException("The second operand of 'in' must be an array.")),
            "contains" => Pair(value, op, (left, right) => new Condition.Contains(Operand.From(left), Operand.From(right))),
            _ => throw new FormatException($"Unknown condition operator '{property.Name}'."),
        };
    }

    private static List<JsonElement> Array(JsonElement value, string op) =>
        value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().ToList()
            : throw new FormatException($"'{op}' expects an array.");

    private static Condition Pair(JsonElement value, string op, Func<JsonElement, JsonElement, Condition> create)
    {
        var items = Array(value, op);
        return items.Count == 2
            ? create(items[0], items[1])
            : throw new FormatException($"'{op}' expects exactly two operands.");
    }
}

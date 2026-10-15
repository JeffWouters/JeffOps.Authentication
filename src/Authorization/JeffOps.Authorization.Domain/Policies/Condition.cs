using System.Text.Json;

namespace JeffOps.Authorization.Domain.Policies;

/// <summary>
/// A compiled ABAC condition. Parsed once from its JSON form (<see cref="ConditionParser"/>) and evaluated many times
/// against an attribute context without re-parsing (docs/DESIGN.md §17, I3). Evaluation is pure: no code execution.
/// </summary>
/// <remarks>
/// The attribute context maps names to JSON values: <c>subject.*</c>, <c>resource.*</c>, <c>environment.*</c> and
/// <c>action</c>. A missing attribute evaluates as undefined, which equals only null/undefined and orders against nothing.
/// </remarks>
public abstract class Condition
{
    /// <summary>The condition that always holds (an empty JSON object).</summary>
    public static Condition Always { get; } = new Constant(true);

    /// <summary>The condition that never holds.</summary>
    public static Condition Never { get; } = new Constant(false);

    public abstract bool Evaluate(IReadOnlyDictionary<string, JsonElement> context);

    internal sealed class Constant(bool value) : Condition
    {
        public override bool Evaluate(IReadOnlyDictionary<string, JsonElement> context) => value;
    }

    internal sealed class All(IReadOnlyList<Condition> conditions) : Condition
    {
        public override bool Evaluate(IReadOnlyDictionary<string, JsonElement> context) =>
            conditions.All(condition => condition.Evaluate(context));
    }

    internal sealed class Any(IReadOnlyList<Condition> conditions) : Condition
    {
        public override bool Evaluate(IReadOnlyDictionary<string, JsonElement> context) =>
            conditions.Any(condition => condition.Evaluate(context));
    }

    internal sealed class Not(Condition inner) : Condition
    {
        public override bool Evaluate(IReadOnlyDictionary<string, JsonElement> context) => !inner.Evaluate(context);
    }

    internal sealed class Comparison(string op, Operand left, Operand right) : Condition
    {
        public override bool Evaluate(IReadOnlyDictionary<string, JsonElement> context)
        {
            var order = JsonValues.Compare(left.Resolve(context), right.Resolve(context));
            return op switch
            {
                "eq" => order == 0,
                "ne" => order is { } ne && ne != 0,
                "lt" => order is { } lt && lt < 0,
                "le" => order is { } le && le <= 0,
                "gt" => order is { } gt && gt > 0,
                "ge" => order is { } ge && ge >= 0,
                _ => false,
            };
        }
    }

    internal sealed class In(Operand value, IReadOnlyList<Operand> candidates) : Condition
    {
        public override bool Evaluate(IReadOnlyDictionary<string, JsonElement> context)
        {
            var resolved = value.Resolve(context);
            return candidates.Any(candidate => JsonValues.Compare(resolved, candidate.Resolve(context)) == 0);
        }
    }

    internal sealed class Contains(Operand array, Operand value) : Condition
    {
        public override bool Evaluate(IReadOnlyDictionary<string, JsonElement> context)
        {
            var resolvedArray = array.Resolve(context);
            var resolvedValue = value.Resolve(context);
            return resolvedArray.ValueKind == JsonValueKind.Array
                && resolvedArray.EnumerateArray().Any(element => JsonValues.Compare(element, resolvedValue) == 0);
        }
    }
}

/// <summary>An operand: a reference to a context attribute, or a literal.</summary>
internal abstract class Operand
{
    public abstract JsonElement Resolve(IReadOnlyDictionary<string, JsonElement> context);

    public static Operand From(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.String)
        {
            var text = element.GetString()!;
            if (IsReference(text))
            {
                return new Reference(text);
            }
        }

        return new Literal(element.Clone());
    }

    private static bool IsReference(string text) =>
        text == "action"
        || text.StartsWith("subject.", StringComparison.Ordinal)
        || text.StartsWith("resource.", StringComparison.Ordinal)
        || text.StartsWith("environment.", StringComparison.Ordinal);

    private sealed class Reference(string name) : Operand
    {
        public override JsonElement Resolve(IReadOnlyDictionary<string, JsonElement> context) =>
            context.TryGetValue(name, out var value) ? value : default;
    }

    private sealed class Literal(JsonElement value) : Operand
    {
        public override JsonElement Resolve(IReadOnlyDictionary<string, JsonElement> context) => value;
    }
}

internal static class JsonValues
{
    /// <summary>-1/0/1 for comparable values of the same kind; null when the kinds differ or don't order.</summary>
    public static int? Compare(JsonElement left, JsonElement right)
    {
        if (left.ValueKind == JsonValueKind.Number && right.ValueKind == JsonValueKind.Number)
        {
            return left.GetDouble().CompareTo(right.GetDouble());
        }

        if (left.ValueKind == JsonValueKind.String && right.ValueKind == JsonValueKind.String)
        {
            return Math.Sign(string.CompareOrdinal(left.GetString(), right.GetString()));
        }

        if (IsBoolean(left) && IsBoolean(right))
        {
            return (left.ValueKind == JsonValueKind.True).CompareTo(right.ValueKind == JsonValueKind.True);
        }

        if (IsNothing(left) && IsNothing(right))
        {
            return 0;
        }

        return null;
    }

    private static bool IsBoolean(JsonElement element) => element.ValueKind is JsonValueKind.True or JsonValueKind.False;

    private static bool IsNothing(JsonElement element) => element.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined;
}

using System.Text.Json;

namespace JeffOps.Authorization.Domain.Policies;

/// <summary>
/// A compiled ABAC condition. Parsed once from its JSON form (<see cref="ConditionParser"/>) and evaluated many times
/// against an attribute context without re-parsing (docs/DESIGN.md §17, I3). Evaluation is pure: no code execution.
/// </summary>
/// <remarks>
/// The attribute context maps names to JSON values: <c>subject.*</c>, <c>resource.*</c>, <c>environment.*</c> and
/// <c>action</c>. Evaluation has three outcomes (<see cref="Test"/>): true, false, or unknown (null) when a comparison involves
/// a missing attribute or values of different kinds. <c>and</c>, <c>or</c> and <c>not</c> combine them as in SQL (false wins
/// <c>and</c>, true wins <c>or</c>, <c>not</c> keeps unknown). A Permit policy applies only when its condition is true; a
/// Deny policy also when it is unknown, so a fence written with missing or mistyped attributes fails closed. Use
/// <c>exists</c> to test for an attribute explicitly.
/// </remarks>
public abstract class Condition
{
    /// <summary>The condition that always holds (an empty JSON object).</summary>
    public static Condition Always { get; } = new Constant(true);

    /// <summary>The condition that never holds.</summary>
    public static Condition Never { get; } = new Constant(false);

    /// <summary>True, false, or null when the outcome is unknown (a missing attribute, values of different kinds).</summary>
    public abstract bool? Test(IReadOnlyDictionary<string, JsonElement> context);

    /// <summary>Whether the condition certainly holds (unknown counts as not holding).</summary>
    public bool Evaluate(IReadOnlyDictionary<string, JsonElement> context) => Test(context) == true;

    internal sealed class Constant(bool value) : Condition
    {
        public override bool? Test(IReadOnlyDictionary<string, JsonElement> context) => value;
    }

    internal sealed class All(IReadOnlyList<Condition> conditions) : Condition
    {
        public override bool? Test(IReadOnlyDictionary<string, JsonElement> context)
        {
            var unknown = false;
            foreach (var condition in conditions)
            {
                switch (condition.Test(context))
                {
                    case false:
                        return false;
                    case null:
                        unknown = true;
                        break;
                }
            }

            return unknown ? null : true;
        }
    }

    internal sealed class Any(IReadOnlyList<Condition> conditions) : Condition
    {
        public override bool? Test(IReadOnlyDictionary<string, JsonElement> context)
        {
            var unknown = false;
            foreach (var condition in conditions)
            {
                switch (condition.Test(context))
                {
                    case true:
                        return true;
                    case null:
                        unknown = true;
                        break;
                }
            }

            return unknown ? null : false;
        }
    }

    internal sealed class Not(Condition inner) : Condition
    {
        public override bool? Test(IReadOnlyDictionary<string, JsonElement> context) => inner.Test(context) is { } value ? !value : null;
    }

    internal sealed class Exists(Operand operand) : Condition
    {
        public override bool? Test(IReadOnlyDictionary<string, JsonElement> context) =>
            operand.Resolve(context).ValueKind is not (JsonValueKind.Undefined or JsonValueKind.Null);
    }

    internal sealed class Comparison(string op, Operand left, Operand right) : Condition
    {
        public override bool? Test(IReadOnlyDictionary<string, JsonElement> context)
        {
            if (JsonValues.Compare(left.Resolve(context), right.Resolve(context)) is not { } order)
            {
                return null;
            }

            return op switch
            {
                "eq" => order == 0,
                "ne" => order != 0,
                "lt" => order < 0,
                "le" => order <= 0,
                "gt" => order > 0,
                "ge" => order >= 0,
                _ => false,
            };
        }
    }

    internal sealed class In(Operand value, IReadOnlyList<Operand> candidates) : Condition
    {
        public override bool? Test(IReadOnlyDictionary<string, JsonElement> context)
        {
            var resolved = value.Resolve(context);
            if (resolved.ValueKind == JsonValueKind.Undefined)
            {
                return null;
            }

            var unknown = false;
            foreach (var candidate in candidates)
            {
                switch (JsonValues.Compare(resolved, candidate.Resolve(context)))
                {
                    case 0:
                        return true;
                    case null:
                        unknown = true;
                        break;
                }
            }

            return unknown ? null : false;
        }
    }

    internal sealed class Contains(Operand array, Operand value) : Condition
    {
        public override bool? Test(IReadOnlyDictionary<string, JsonElement> context)
        {
            var resolvedArray = array.Resolve(context);
            var resolvedValue = value.Resolve(context);
            if (resolvedArray.ValueKind != JsonValueKind.Array || resolvedValue.ValueKind == JsonValueKind.Undefined)
            {
                return null;
            }

            return resolvedArray.EnumerateArray().Any(element => JsonValues.Compare(element, resolvedValue) == 0);
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
    /// <summary>
    /// -1/0/1 for comparable values of the same kind (explicit JSON nulls compare equal); null when either is missing, the
    /// kinds differ, or they don't order.
    /// </summary>
    public static int? Compare(JsonElement left, JsonElement right)
    {
        if (left.ValueKind == JsonValueKind.Undefined || right.ValueKind == JsonValueKind.Undefined)
        {
            return null;
        }

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

        if (left.ValueKind == JsonValueKind.Null && right.ValueKind == JsonValueKind.Null)
        {
            return 0;
        }

        return null;
    }

    private static bool IsBoolean(JsonElement element) => element.ValueKind is JsonValueKind.True or JsonValueKind.False;

}

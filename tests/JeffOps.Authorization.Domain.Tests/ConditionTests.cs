using System.Text.Json;
using JeffOps.Authorization.Domain.Policies;

namespace JeffOps.Authorization.Domain.Tests;

public sealed class ConditionTests
{
    private static Dictionary<string, JsonElement> Context(params (string Key, object? Value)[] pairs) =>
        pairs.ToDictionary(pair => pair.Key, pair => JsonSerializer.SerializeToElement(pair.Value));

    private static bool Evaluate(string? condition, Dictionary<string, JsonElement> context) =>
        ConditionParser.Parse(condition).Evaluate(context);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("{}")]
    [InlineData("""{"true":true}""")]
    public void Empty_or_true_is_always_true(string? condition) => Evaluate(condition, Context()).ShouldBeTrue();

    [Fact]
    public void Eq_matches_resolved_attribute_to_literal()
    {
        var context = Context(("subject.tid", "t-1"));

        Evaluate("""{"eq":["subject.tid","t-1"]}""", context).ShouldBeTrue();
        Evaluate("""{"eq":["subject.tid","t-2"]}""", context).ShouldBeFalse();
    }

    [Fact]
    public void Ne_compares_two_attributes()
    {
        var context = Context(("resource.tenantId", "t-2"), ("subject.tid", "t-1"));

        Evaluate("""{"ne":["resource.tenantId","subject.tid"]}""", context).ShouldBeTrue();
    }

    [Fact]
    public void Numeric_comparisons_order_correctly()
    {
        var context = Context(("environment.utcHour", 22));

        Evaluate("""{"gt":["environment.utcHour",18]}""", context).ShouldBeTrue();
        Evaluate("""{"le":["environment.utcHour",22]}""", context).ShouldBeTrue();
        Evaluate("""{"lt":["environment.utcHour",18]}""", context).ShouldBeFalse();
        Evaluate("""{"ge":["environment.utcHour",23]}""", context).ShouldBeFalse();
    }

    [Fact]
    public void In_checks_membership()
    {
        var context = Context(("subject.lvl", "Tenant"));

        Evaluate("""{"in":["subject.lvl",["Root","Tenant"]]}""", context).ShouldBeTrue();
        Evaluate("""{"in":["subject.lvl",["Root","Organization"]]}""", context).ShouldBeFalse();
    }

    [Fact]
    public void Contains_checks_an_array_attribute()
    {
        var context = Context(("subject.groups", new[] { "read", "write" }));

        Evaluate("""{"contains":["subject.groups","write"]}""", context).ShouldBeTrue();
        Evaluate("""{"contains":["subject.groups","delete"]}""", context).ShouldBeFalse();
    }

    [Fact]
    public void And_or_not_compose()
    {
        var context = Context(("subject.lvl", "Tenant"), ("environment.utcHour", 9));

        Evaluate("""{"and":[{"eq":["subject.lvl","Tenant"]},{"lt":["environment.utcHour",17]}]}""", context).ShouldBeTrue();
        Evaluate("""{"or":[{"eq":["subject.lvl","Root"]},{"lt":["environment.utcHour",17]}]}""", context).ShouldBeTrue();
        Evaluate("""{"not":{"eq":["subject.lvl","Root"]}}""", context).ShouldBeTrue();
    }

    [Fact]
    public void A_missing_attribute_matches_no_comparison()
    {
        var context = Context(("subject.tid", "t-1"));

        Evaluate("""{"eq":["resource.tenantId","t-1"]}""", context).ShouldBeFalse();
        Evaluate("""{"ne":["resource.tenantId","t-1"]}""", context).ShouldBeFalse();
        Evaluate("""{"gt":["resource.tenantId","t-1"]}""", context).ShouldBeFalse();
    }

    [Fact]
    public void A_compiled_condition_is_reusable_across_contexts()
    {
        var condition = ConditionParser.Parse("""{"eq":["subject.tid","t-1"]}""");

        condition.Evaluate(Context(("subject.tid", "t-1"))).ShouldBeTrue();
        condition.Evaluate(Context(("subject.tid", "t-2"))).ShouldBeFalse();
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("""{"between":[1,2]}""")]
    [InlineData("""{"eq":["a"]}""")]
    [InlineData("""{"eq":["a","b"],"ne":["a","b"]}""")]
    [InlineData("""{"and":{"eq":["a","b"]}}""")]
    [InlineData("""{"in":["subject.lvl","Root"]}""")]
    [InlineData("[]")]
    public void Invalid_conditions_are_rejected_at_parse_time(string condition)
    {
        Should.Throw<FormatException>(() => ConditionParser.Parse(condition));
        ConditionParser.TryParse(condition, out _, out var error).ShouldBeFalse();
        error.ShouldNotBeNullOrWhiteSpace();
    }
}

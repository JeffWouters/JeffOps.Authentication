using JeffOps.Authentication.SharedKernel.Results;

namespace JeffOps.Authentication.SharedKernel.Tests;

public sealed class ResultTests
{
    private static readonly Error SomeError = Error.Conflict("already_exists", "It already exists.");

    [Fact]
    public void Success_has_no_error()
    {
        var result = Result.Success();

        result.IsSuccess.ShouldBeTrue();
        result.IsFailure.ShouldBeFalse();
        result.Error.ShouldBe(Error.None);
    }

    [Fact]
    public void Failure_carries_the_error()
    {
        var result = Result.Failure(SomeError);

        result.IsFailure.ShouldBeTrue();
        result.Error.ShouldBe(SomeError);
    }

    [Fact]
    public void Failure_without_an_error_is_rejected() =>
        Should.Throw<ArgumentException>(() => Result.Failure(Error.None));

    [Fact]
    public void Value_of_a_success_is_returned()
    {
        Result<int> result = 42;

        result.IsSuccess.ShouldBeTrue();
        result.Value.ShouldBe(42);
    }

    [Fact]
    public void Value_of_a_failure_throws()
    {
        Result<int> result = SomeError;

        result.IsFailure.ShouldBeTrue();
        Should.Throw<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void Match_picks_the_branch()
    {
        Result<int> success = 1;
        Result<int> failure = SomeError;

        success.Match(value => $"value {value}", error => error.Code).ShouldBe("value 1");
        failure.Match(value => $"value {value}", error => error.Code).ShouldBe("already_exists");
    }

    [Fact]
    public void Validation_error_carries_its_failures()
    {
        var error = Error.Validation([new ValidationFailure("Name", "Required.")]);

        error.Type.ShouldBe(ErrorType.Validation);
        error.Code.ShouldBe("validation_failed");
        error.Failures.ShouldHaveSingleItem().Property.ShouldBe("Name");
    }

    [Fact]
    public void Non_validation_errors_have_no_failures() =>
        SomeError.Failures.ShouldBeEmpty();
}

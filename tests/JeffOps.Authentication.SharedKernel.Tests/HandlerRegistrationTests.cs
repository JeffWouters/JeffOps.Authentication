using JeffOps.Authentication.SharedKernel.DependencyInjection;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Results;
using JeffOps.Authentication.SharedKernel.Validation;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.SharedKernel.Tests;

public sealed class HandlerRegistrationTests
{
    [Fact]
    public async Task AddHandler_registers_the_handler_under_its_interface()
    {
        await using var provider = new ServiceCollection()
            .AddHandler<CreateThingHandler>()
            .BuildServiceProvider();

        var handler = provider.GetRequiredService<ICommandHandler<CreateThing, Guid>>();

        handler.ShouldBeOfType<CreateThingHandler>();
    }

    [Fact]
    public void AddHandler_rejects_a_type_that_is_not_a_handler() =>
        Should.Throw<ArgumentException>(() => new ServiceCollection().AddHandler<NotAHandler>());

    [Fact]
    public async Task Validation_decorator_short_circuits_with_the_validation_failures()
    {
        await using var provider = new ServiceCollection()
            .AddHandler<CreateThingHandler>()
            .AddValidator<CreateThingValidator>()
            .AddHandlerValidation()
            .BuildServiceProvider();

        var handler = provider.GetRequiredService<ICommandHandler<CreateThing, Guid>>();
        var result = await handler.HandleAsync(new CreateThing(string.Empty), TestContext.Current.CancellationToken);

        result.IsFailure.ShouldBeTrue();
        result.Error.Type.ShouldBe(ErrorType.Validation);
        result.Error.Failures.ShouldHaveSingleItem().Property.ShouldBe(nameof(CreateThing.Name));
    }

    [Fact]
    public async Task Validation_decorator_calls_the_handler_when_input_is_valid()
    {
        await using var provider = new ServiceCollection()
            .AddHandler<CreateThingHandler>()
            .AddValidator<CreateThingValidator>()
            .AddHandlerValidation()
            .BuildServiceProvider();

        var handler = provider.GetRequiredService<ICommandHandler<CreateThing, Guid>>();
        var result = await handler.HandleAsync(new CreateThing("thing"), TestContext.Current.CancellationToken);

        result.IsSuccess.ShouldBeTrue();
        result.Value.ShouldBe(CreateThingHandler.CreatedId);
    }

    [Fact]
    public async Task Validation_decorator_applies_to_handlers_without_validators()
    {
        await using var provider = new ServiceCollection()
            .AddHandler<DeleteThingHandler>()
            .AddHandlerValidation()
            .BuildServiceProvider();

        var handler = provider.GetRequiredService<ICommandHandler<DeleteThing>>();
        var result = await handler.HandleAsync(new DeleteThing(), TestContext.Current.CancellationToken);

        result.IsSuccess.ShouldBeTrue();
    }

    [Fact]
    public void Decorating_records_the_original_implementation()
    {
        var services = new ServiceCollection()
            .AddHandler<CreateThingHandler>()
            .AddHandlerValidation();

        services.ShouldContain(descriptor =>
            descriptor.ImplementationInstance is DecoratedService
            && ((DecoratedService)descriptor.ImplementationInstance).ImplementationType == typeof(CreateThingHandler));
    }

    [Fact]
    public async Task Decorators_stack_in_registration_order()
    {
        var services = new ServiceCollection()
            .AddHandler<CreateThingHandler>()
            .AddValidator<CreateThingValidator>()
            .AddHandlerValidation()
            .DecorateOpenGeneric(typeof(ICommandHandler<,>), typeof(CountingHandler<,>));
        services.AddSingleton<CallCounter>();
        await using var provider = services.BuildServiceProvider();

        var handler = provider.GetRequiredService<ICommandHandler<CreateThing, Guid>>();
        await handler.HandleAsync(new CreateThing(string.Empty), TestContext.Current.CancellationToken);

        // The counter wraps the validator, so it sees the call even though validation short-circuits.
        provider.GetRequiredService<CallCounter>().Calls.ShouldBe(1);
    }

    public sealed record CreateThing(string Name);

    public sealed record DeleteThing;

    public sealed class CreateThingHandler : ICommandHandler<CreateThing, Guid>
    {
        public static readonly Guid CreatedId = Guid.Parse("8f4e2c1a-0000-4000-8000-000000000001");

        public Task<Result<Guid>> HandleAsync(CreateThing command, CancellationToken cancellationToken) =>
            Task.FromResult<Result<Guid>>(CreatedId);
    }

    public sealed class DeleteThingHandler : ICommandHandler<DeleteThing>
    {
        public Task<Result> HandleAsync(DeleteThing command, CancellationToken cancellationToken) =>
            Task.FromResult(Result.Success());
    }

    public sealed class CreateThingValidator : IValidator<CreateThing>
    {
        public IEnumerable<ValidationFailure> Validate(CreateThing instance)
        {
            if (string.IsNullOrWhiteSpace(instance.Name))
            {
                yield return new ValidationFailure(nameof(CreateThing.Name), "Name is required.");
            }
        }
    }

    public sealed class NotAHandler;

    public sealed class CallCounter
    {
        public int Calls { get; set; }
    }

    public sealed class CountingHandler<TCommand, TResult>(ICommandHandler<TCommand, TResult> inner, CallCounter counter)
        : ICommandHandler<TCommand, TResult>
    {
        public Task<Result<TResult>> HandleAsync(TCommand command, CancellationToken cancellationToken)
        {
            counter.Calls++;
            return inner.HandleAsync(command, cancellationToken);
        }
    }
}

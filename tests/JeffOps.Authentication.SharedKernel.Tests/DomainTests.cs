using JeffOps.Authentication.SharedKernel.DependencyInjection;
using JeffOps.Authentication.SharedKernel.Domain;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.SharedKernel.Tests;

public sealed class DomainTests
{
    [Fact]
    public void Entities_with_the_same_type_and_id_are_equal()
    {
        var id = Guid.NewGuid();

        (new Thing(id) == new Thing(id)).ShouldBeTrue();
        new Thing(id).GetHashCode().ShouldBe(new Thing(id).GetHashCode());
    }

    [Fact]
    public void Entities_of_different_types_with_the_same_id_are_not_equal()
    {
        var id = Guid.NewGuid();

        new Thing(id).Equals(new OtherThing(id)).ShouldBeFalse();
    }

    [Fact]
    public void Aggregate_collects_and_clears_raised_events()
    {
        var thing = new Thing(Guid.NewGuid());

        thing.Rename("new name");

        thing.DomainEvents.ShouldHaveSingleItem().ShouldBeOfType<ThingRenamed>().Name.ShouldBe("new name");
        thing.ClearDomainEvents();
        thing.DomainEvents.ShouldBeEmpty();
    }

    [Fact]
    public async Task Dispatcher_calls_every_handler_for_the_event_type()
    {
        var log = new List<string>();
        var services = new ServiceCollection()
            .AddDomainEventDispatcher()
            .AddDomainEventHandler<FirstHandler>()
            .AddDomainEventHandler<SecondHandler>();
        services.AddSingleton(log);
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        var dispatcher = scope.ServiceProvider.GetRequiredService<IDomainEventDispatcher>();
        await dispatcher.DispatchAsync([new ThingRenamed("a"), new ThingRenamed("b")], TestContext.Current.CancellationToken);

        log.ShouldBe(["first:a", "second:a", "first:b", "second:b"]);
    }

    [Fact]
    public async Task Dispatcher_ignores_events_without_handlers()
    {
        await using var provider = new ServiceCollection().AddDomainEventDispatcher().BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();

        var dispatcher = scope.ServiceProvider.GetRequiredService<IDomainEventDispatcher>();

        await Should.NotThrowAsync(() => dispatcher.DispatchAsync([new ThingRenamed("a")], TestContext.Current.CancellationToken));
    }

    public sealed record ThingRenamed(string Name) : IDomainEvent;

    public sealed class Thing(Guid id) : AggregateRoot<Guid>(id)
    {
        public void Rename(string name) => Raise(new ThingRenamed(name));
    }

    public sealed class OtherThing(Guid id) : AggregateRoot<Guid>(id);

    public sealed class FirstHandler(List<string> log) : IDomainEventHandler<ThingRenamed>
    {
        public Task HandleAsync(ThingRenamed domainEvent, CancellationToken cancellationToken)
        {
            log.Add($"first:{domainEvent.Name}");
            return Task.CompletedTask;
        }
    }

    public sealed class SecondHandler(List<string> log) : IDomainEventHandler<ThingRenamed>
    {
        public Task HandleAsync(ThingRenamed domainEvent, CancellationToken cancellationToken)
        {
            log.Add($"second:{domainEvent.Name}");
            return Task.CompletedTask;
        }
    }
}

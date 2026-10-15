using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.Domain.Accounts;
using JeffOps.Authentication.Domain.PersonalAccessTokens;
using JeffOps.Authentication.SharedKernel.Domain;

namespace JeffOps.Authentication.Application.Events;

/// <summary>
/// Translates committed domain events into integration events for other services (docs/DESIGN.md §15).
/// </summary>
public sealed class IntegrationEventPublishers(IEventPublisher publisher, TimeProvider time) :
    IDomainEventHandler<AccountRegistered>,
    IDomainEventHandler<AccountStatusChanged>,
    IDomainEventHandler<PersonalAccessTokenCreated>,
    IDomainEventHandler<PersonalAccessTokenRevoked>
{
    public Task HandleAsync(AccountRegistered domainEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);
        return publisher.PublishAsync(new AccountRegisteredEvent(domainEvent.AccountId, domainEvent.Email) { OccurredAt = time.GetUtcNow() }, cancellationToken);
    }

    public Task HandleAsync(AccountStatusChanged domainEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);
        return publisher.PublishAsync(new AccountStatusChangedEvent(domainEvent.AccountId, domainEvent.Disabled) { OccurredAt = time.GetUtcNow() }, cancellationToken);
    }

    public Task HandleAsync(PersonalAccessTokenCreated domainEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);
        return publisher.PublishAsync(new PersonalAccessTokenCreatedEvent(domainEvent.TokenId, domainEvent.AccountId) { OccurredAt = time.GetUtcNow() }, cancellationToken);
    }

    public Task HandleAsync(PersonalAccessTokenRevoked domainEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(domainEvent);
        return publisher.PublishAsync(new PersonalAccessTokenRevokedEvent(domainEvent.TokenId, domainEvent.AccountId) { OccurredAt = time.GetUtcNow() }, cancellationToken);
    }
}

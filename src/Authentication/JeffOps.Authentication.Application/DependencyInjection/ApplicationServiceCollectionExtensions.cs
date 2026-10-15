using JeffOps.Authentication.Abstractions.Claims;
using JeffOps.Authentication.Abstractions.Tenancy;
using JeffOps.Authentication.Application.Events;
using JeffOps.Authentication.Application.Features.Accounts;
using JeffOps.Authentication.Application.Features.Federation.CompleteExternalSignIn;
using JeffOps.Authentication.Application.Features.Grants.ClientCredentials;
using JeffOps.Authentication.Application.Features.Grants.ExchangePat;
using JeffOps.Authentication.Application.Features.PersonalAccessTokens;
using JeffOps.Authentication.Application.Features.Sessions.RefreshSession;
using JeffOps.Authentication.Application.Features.Sessions.StartSession;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.SharedKernel.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace JeffOps.Authentication.Application.DependencyInjection;

public static class ApplicationServiceCollectionExtensions
{
    /// <summary>
    /// Registers the token server's use cases, each explicitly (docs/DESIGN.md §6.1), with validation decorators. Called by
    /// <c>AddJeffOpsAuthentication</c>; hosts don't call it directly.
    /// </summary>
    public static IServiceCollection AddJeffOpsAuthenticationApplication(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(ClaimNames.Default);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ITenantDirectory, NoTenantDirectory>();
        services.TryAddScoped<Federation.IHomeRealmDirectory, Federation.NoHomeRealms>();
        services.TryAddScoped<SessionBuilder>();

        services
            .AddHandler<StartSessionHandler>()
            .AddHandler<RefreshSessionHandler>()
            .AddHandler<ClientCredentialsHandler>()
            .AddHandler<ExchangePatHandler>()
            .AddHandler<CreatePatHandler>()
            .AddValidator<CreatePatValidator>()
            .AddHandler<ListPatsHandler>()
            .AddHandler<RevokePatHandler>()
            .AddHandler<SetAccountStatusHandler>()
            .AddHandler<GetAccountContactHandler>()
            .AddHandler<FindAccountByEmailHandler>()
            .AddHandler<CompleteExternalSignInHandler>()
            .AddHandlerValidation();

        services.AddDomainEventDispatcher();
        services.AddDomainEventHandler<IntegrationEventPublishers>();

        return services;
    }
}

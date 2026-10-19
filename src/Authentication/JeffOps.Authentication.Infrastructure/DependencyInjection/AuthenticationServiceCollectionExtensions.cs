using JeffOps.Authentication.Abstractions.Auditing;
using JeffOps.Authentication.Abstractions.Messaging;
using JeffOps.Authentication.Application;
using JeffOps.Authentication.Application.Abstractions;
using JeffOps.Authentication.Application.Sessions;
using JeffOps.Authentication.Application.DependencyInjection;
using JeffOps.Authentication.Infrastructure.Defaults;
using JeffOps.Authentication.Infrastructure.Keys;
using JeffOps.Authentication.Infrastructure.Persistence;
using JeffOps.Authentication.Infrastructure.Server;
using JeffOps.Authentication.SharedKernel.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace JeffOps.Authentication.Infrastructure.DependencyInjection;

/// <summary>Infrastructure choices on the <see cref="AuthenticationBuilder"/>.</summary>
public static class AuthenticationBuilderExtensions
{
    /// <summary>
    /// Configures the store's database provider. Persistence packages call this; tests may too. Contexts are pooled (one per concurrent request, reused): <paramref name="configure"/> runs once, with the root service provider, so it must not resolve scoped services.
    /// </summary>
    public static AuthenticationBuilder UseDatabase(this AuthenticationBuilder builder, Action<IServiceProvider, DbContextOptionsBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        builder.Services.AddDbContextPool<AuthenticationDbContext>((provider, options) =>
        {
            configure(provider, options);
            options.UseOpenIddict();
        });
        return builder;
    }

    /// <summary>Signs tokens with configured certificates (<see cref="SigningCertificateOptions"/>) instead of database keys.</summary>
    public static AuthenticationBuilder UseCertificateSigning(this AuthenticationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.AddOptions<SigningCertificateOptions>().Bind(builder.Configuration.GetSection(SigningCertificateOptions.SectionName));
        return builder.UseSigningKeyProvider<CertificateKeyProvider>();
    }
}

/// <summary>Registers the JeffOps token server.</summary>
public static class AuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// Adds the JeffOps token server (docs/DESIGN.md §7): the use cases, the OpenIddict server and local token validation, the
    /// token keys (database by default, rotating), client and scope seeding, and default logging sinks for audit records and
    /// integration events. Add a database with a persistence package (for example <c>AddSqlServerPersistence</c>) and map the
    /// endpoints with <c>MapJeffOpsAuthentication</c>. Options bind from <see cref="TokenServerOptions.SectionName"/>.
    /// </summary>
    public static AuthenticationBuilder AddJeffOpsAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddOptions<TokenServerOptions>()
            .Bind(configuration.GetSection(TokenServerOptions.SectionName))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<TokenServerOptions>, TokenServerOptionsValidator>();
        services.AddOptions<SigningKeyOptions>().Bind(configuration.GetSection(SigningKeyOptions.SectionName));
        services.AddOptions<Application.Federation.FederationOptions>().Bind(configuration.GetSection(Application.Federation.FederationOptions.SectionName));

        services.AddJeffOpsAuthenticationApplication();
        services.TryAddScoped<IAccountRepository, AccountRepository>();
        services.TryAddScoped<IPersonalAccessTokenRepository, PersonalAccessTokenRepository>();
        services.TryAddScoped<IUnitOfWork, EfUnitOfWork>();
        services.TryAddSingleton<IAuditSink, LoggingAuditSink>();
        services.TryAddSingleton<IEventPublisher, InProcessEventPublisher>();

        services.AddDataProtection();
        services.AddMemoryCache();
        services.AddAuthorization(); // The endpoints require it; idempotent when the host adds its own policies.
        // One-time values (DPoP proofs, SAML assertions) are remembered in the database, so they count once across instances.
        services.TryAddSingleton<Abstractions.Replay.IReplayCache, DatabaseReplayCache>();
        services.TryAddSingleton<DatabaseKeyStore>();
        services.TryAddSingleton<ClientSnapshots>();
        services.TryAddSingleton<ITokenKeyProvider>(provider => provider.GetRequiredService<DatabaseKeyStore>());
        services.AddHostedService<KeyRotationService>();

        services.AddOpenIddict()
            .AddCore(core =>
            {
                core.UseEntityFrameworkCore().UseDbContext<AuthenticationDbContext>();

                // Clients come from configuration: each request reads its client from a minute-old snapshot, not the database.
                core.ReplaceApplicationStore<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication, CachedApplicationStore>(ServiceLifetime.Scoped);
            })
            .AddServer(server =>
            {
                server.SetAuthorizationEndpointUris("connect/authorize")
                    .SetTokenEndpointUris("connect/token")
                    .SetUserInfoEndpointUris("connect/userinfo")
                    .SetEndSessionEndpointUris("connect/endsession")
                    .SetRevocationEndpointUris("connect/revoke")
                    .SetIntrospectionEndpointUris("connect/introspect")
                    .SetPushedAuthorizationEndpointUris("connect/par")
                    .SetDeviceAuthorizationEndpointUris("connect/device")
                    .SetEndUserVerificationEndpointUris("connect/verify");

                server.AllowAuthorizationCodeFlow()
                    .RequireProofKeyForCodeExchange()
                    .AllowRefreshTokenFlow()
                    .AllowClientCredentialsFlow()
                    .AllowDeviceAuthorizationFlow();

                server.RegisterScopes(Scopes.OpenId, Scopes.Profile, Scopes.Email, Scopes.OfflineAccess);
                server.DisableAccessTokenEncryption();

                // DPoP (RFC 9449): bound tokens are of type DPoP, and discovery says which proof algorithms are accepted.
                server.AddEventHandler<OpenIddictServerEvents.ApplyTokenResponseContext>(handler => handler
                    .UseInlineHandler(context =>
                    {
                        if (context.Response.AccessToken is not null
                            && Microsoft.AspNetCore.OpenIddictServerAspNetCoreHelpers.GetHttpRequest(context.Transaction)?.Headers.ContainsKey(Abstractions.Dpop.DpopProofValidator.HeaderName) == true)
                        {
                            context.Response.TokenType = Abstractions.Dpop.DpopProofValidator.Scheme;
                        }

                        return default;
                    })
                    .SetOrder(int.MinValue + 100_000));
                server.AddEventHandler<OpenIddictServerEvents.GenerateTokenContext>(handler => handler
                    .UseInlineHandler(context =>
                    {
                        // Codes and refresh tokens keep the binding claim as it is; the access token gets cnf.jkt instead.
                        if (context.TokenType == OpenIddict.Abstractions.OpenIddictConstants.TokenTypeIdentifiers.AccessToken
                            && context.SecurityTokenDescriptor.Subject is { } subject
                            && subject.FindFirst(Application.Sessions.DpopBinding.ClaimType) is { } binding)
                        {
                            subject.RemoveClaim(binding);
                            context.SecurityTokenDescriptor.Claims ??= new Dictionary<string, object>(StringComparer.Ordinal);
                            context.SecurityTokenDescriptor.Claims["cnf"] = new Dictionary<string, object> { ["jkt"] = binding.Value };
                        }

                        return default;
                    })
                    .SetOrder(OpenIddictServerHandlers.Protection.GenerateIdentityModelToken.Descriptor.Order - 500));
                server.AddEventHandler<OpenIddictServerEvents.HandleConfigurationRequestContext>(handler => handler
                    .UseInlineHandler(context =>
                    {
                        context.Metadata["dpop_signing_alg_values_supported"] = new OpenIddict.Abstractions.OpenIddictParameter([.. Abstractions.Dpop.DpopProofValidator.Algorithms]);

                        // OpenID Connect Back-Channel Logout 1.0: logout tokens carry sid, and ID tokens name the session.
                        context.Metadata["backchannel_logout_supported"] = true;
                        context.Metadata["backchannel_logout_session_supported"] = true;
                        return default;
                    }));

                BoundAccessTokens.Register(server);
                PushedAuthorizationDpop.Register(server);
                server.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableUserInfoEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough()
                    .EnableEndUserVerificationEndpointPassthrough();
            })
            .AddValidation(validation =>
            {
                validation.UseLocalServer();
                validation.UseAspNetCore();

                // A revoked token (connect/revoke, sign-out everywhere, a disabled account) stops working here at once.
                validation.EnableTokenEntryValidation();
                BoundAccessTokens.Register(validation);
            });

        // Settings that depend on bound options and the environment.
        services.AddOptions<OpenIddictServerOptions>()
            .Configure<IOptions<TokenServerOptions>, IEnumerable<ExtensionGrantRegistration>>((server, tokenServer, extensions) =>
            {
                ApplyOptions(server, tokenServer.Value);
                foreach (var extension in extensions)
                {
                    server.GrantTypes.Add(tokenServer.Value.ExtensionGrantType(extension.Name));
                }
            });
        services.AddOptions<OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreOptions>()
            .Configure<IHostEnvironment>((aspNetCore, environment) => aspNetCore.DisableTransportSecurityRequirement = environment.IsDevelopment());
        services.AddSingleton<IConfigureOptions<OpenIddictServerOptions>, ServerCredentialsSetup>();
        services.AddSingleton<IOptionsChangeTokenSource<OpenIddictServerOptions>, KeysChangeTokenSource<OpenIddictServerOptions>>();
        services.AddSingleton<IOptionsChangeTokenSource<OpenIddict.Validation.OpenIddictValidationOptions>, KeysChangeTokenSource<OpenIddict.Validation.OpenIddictValidationOptions>>();

        services.AddHostedService<AuthenticationStartup>();
        services.AddHttpClient(BackchannelLogoutNotifier.HttpClientName);
        services.AddHttpClient(ExternalTokenValidator.HttpClientName);
        services.TryAddSingleton<Application.Features.Grants.WorkloadIdentity.IExternalTokenValidator, ExternalTokenValidator>();
        services.AddDomainEventHandler<BackchannelLogoutNotifier>();
        services.TryAddScoped<IEndedSessions, DatabaseEndedSessions>();
        services.TryAddScoped<Application.Federation.IExternalSessions, DatabaseExternalSessions>();
        services.TryAddScoped<ISessionLogoutNotifier, BackchannelLogoutNotifier>();

        return new AuthenticationBuilder(services, configuration);
    }

    internal static void ApplyOptions(OpenIddictServerOptions server, TokenServerOptions options)
    {
        if (options.Issuer is not null)
        {
            server.Issuer = options.Issuer;
        }

        server.AccessTokenLifetime = options.AccessTokenLifetime;
        server.RefreshTokenLifetime = options.SessionLifetime;
        server.DisableSlidingRefreshTokenExpiration = true;
        server.RefreshTokenReuseLeeway = options.RefreshTokenReuseLeeway;
        server.GrantTypes.Add(options.PatGrantType);

        foreach (var scope in options.ApiScopes.Keys)
        {
            server.Scopes.Add(scope);
        }
    }

    private sealed class TokenServerOptionsValidator(IHostEnvironment environment) : IValidateOptions<TokenServerOptions>
    {
        public ValidateOptionsResult Validate(string? name, TokenServerOptions options)
        {
            var failures = new List<string>();

            if (options.Issuer is null && !environment.IsDevelopment())
            {
                failures.Add($"{TokenServerOptions.SectionName}:Issuer is required outside Development.");
            }

            if (options.Issuer is { IsAbsoluteUri: false })
            {
                failures.Add($"{TokenServerOptions.SectionName}:Issuer must be an absolute URL.");
            }

            if (options.SessionLifetime <= TimeSpan.Zero || options.AccessTokenLifetime <= TimeSpan.Zero)
            {
                failures.Add("Session and access-token lifetimes must be positive.");
            }

            if (options.Pat.MaxLifetime <= TimeSpan.Zero || string.IsNullOrWhiteSpace(options.Pat.Prefix))
            {
                failures.Add("Personal access tokens need a positive maximum lifetime and a prefix.");
            }

            failures.AddRange(options.Clients
                .GroupBy(client => client.ClientId, StringComparer.Ordinal)
                .Where(group => group.Count() > 1)
                .Select(group => $"Client '{group.Key}' is configured more than once."));

            return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
        }
    }
}

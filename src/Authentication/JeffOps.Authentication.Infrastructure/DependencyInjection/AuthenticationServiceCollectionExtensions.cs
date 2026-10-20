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
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
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
            // Every SQL command at Debug, not Information: a host's default level would otherwise format each one. Set first, so
            // the host's own configuration wins.
            options.ConfigureWarnings(warnings => warnings.Log((RelationalEventId.CommandExecuted, LogLevel.Debug)));
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

        // Outside Development the key ring must persist where every instance finds it, encrypted at rest (docs/DESIGN.md §16):
        // it protects the token keys, the sign-in cookie and every sealed value, and one kept in memory signs everyone out at
        // each restart (and differs per instance).
        services.AddOptions<Microsoft.AspNetCore.DataProtection.KeyManagement.KeyManagementOptions>()
            .Validate<IHostEnvironment>(
                (keys, environment) => environment.IsDevelopment() || (keys.XmlRepository is not null && keys.XmlEncryptor is not null),
                "Outside Development, the Data Protection key ring must be persisted (PersistKeysTo...) and protected at rest (ProtectKeysWith...). " +
                "AddJeffOpsDataProtection with JeffOps:DataProtection:KekCertificate and KeyDirectory (or PersistKeysToRedis) does both.")
            .ValidateOnStart();
        services.AddOptions<Abstractions.RateLimiting.RateLimitOptions>().Bind(configuration.GetSection(Abstractions.RateLimiting.RateLimitOptions.SectionName));
        services.TryAddSingleton(provider => new Abstractions.RateLimiting.RequestRateLimiter(provider.GetService<TimeProvider>() ?? TimeProvider.System));
        services.AddMemoryCache();
        services.AddAuthorization(); // The endpoints require it; idempotent when the host adds its own policies.
        services.TryAddEnumerable(ServiceDescriptor.Singleton<Microsoft.AspNetCore.Authorization.IAuthorizationHandler, AccountAudienceHandler>());
        services.AddHttpContextAccessor();
        services.Replace(ServiceDescriptor.Scoped<Application.Federation.IPendingLinks, CookiePendingLinks>());
        services.AddAuthorizationBuilder().AddPolicy(AccountApi.PolicyName, policy => policy
            .AddAuthenticationSchemes(OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .AddRequirements(new AccountAudienceRequirement()));
        // One-time values (DPoP proofs, SAML assertions) are remembered in the database, so they count once across instances.
        services.TryAddSingleton<Abstractions.Replay.IReplayCache, DatabaseReplayCache>();
        services.TryAddSingleton<DatabaseKeyStore>();
        services.TryAddSingleton<ClientSnapshots>();
        services.TryAddSingleton<ITokenKeyProvider>(provider => provider.GetRequiredService<DatabaseKeyStore>());
        // Migrations and seeding first: hosted services start in order, and the background loops below need the schema.
        services.AddHostedService<AuthenticationStartup>();
        services.AddHostedService<KeyRotationService>();
        services.AddHostedService<StoreMaintenance>();

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

                // PKCE with S256 only: plain (or a challenge without a method, which means plain) is refused (§16).
                server.Configure(options =>
                {
                    options.CodeChallengeMethods.Clear();
                    options.CodeChallengeMethods.Add(CodeChallengeMethods.Sha256);
                });

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
                ProtocolRateLimits.Register(server);
                ClientAssertionReplay.Register(server);
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

        server.Scopes.Add(AccountApi.Scope);
    }

    private sealed class TokenServerOptionsValidator(IHostEnvironment environment, Abstractions.Claims.ClaimNames names) : IValidateOptions<TokenServerOptions>
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

            if (string.IsNullOrWhiteSpace(options.AccountAudience)
                || options.ApiScopes.ContainsKey(AccountApi.Scope)
                || options.ApiScopes.Values.Any(audiences => audiences.Contains(options.AccountAudience, StringComparer.Ordinal)))
            {
                failures.Add($"The '{AccountApi.Scope}' scope and the account audience '{options.AccountAudience}' are reserved for the token server's own APIs; no API scope may use them.");
            }

            if (options.PruneAfter < TimeSpan.Zero || options.PruneInterval < TimeSpan.Zero)
            {
                failures.Add("PruneAfter and PruneInterval can't be negative (a zero PruneInterval disables pruning).");
            }

            if (options.Mfa.StepUpMaxAge < TimeSpan.Zero)
            {
                failures.Add("Mfa:StepUpMaxAge can't be negative (zero lets one multi-factor sign-in cover the whole session).");
            }

            if (options.Pat.MaxLifetime <= TimeSpan.Zero || string.IsNullOrWhiteSpace(options.Pat.Prefix))
            {
                failures.Add("Personal access tokens need a positive maximum lifetime and a prefix.");
            }

            failures.AddRange(options.Clients
                .SelectMany(client => client.UpstreamClaims
                    .Where(type => Application.Federation.UpstreamIdentity.IsReserved(type, names))
                    .Select(type => $"Client '{client.ClientId}' can't receive '{type}' from a provider (UpstreamClaims): it is this server's own claim.")));

            failures.AddRange(options.Clients
                .Where(client => client.SkipLoginPage && !(client.Providers is [var only] && only != Application.Federation.ClientProviders.Local))
                .Select(client => $"Client '{client.ClientId}' can skip the login page (SkipLoginPage) only with exactly one provider that isn't '{Application.Federation.ClientProviders.Local}'."));

            failures.AddRange(options.Clients
                .GroupBy(client => client.ClientId, StringComparer.Ordinal)
                .Where(group => group.Count() > 1)
                .Select(group => $"Client '{group.Key}' is configured more than once."));

            return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
        }
    }
}

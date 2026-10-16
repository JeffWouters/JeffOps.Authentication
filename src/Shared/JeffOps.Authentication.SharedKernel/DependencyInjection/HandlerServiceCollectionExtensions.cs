using JeffOps.Authentication.SharedKernel.Domain;
using JeffOps.Authentication.SharedKernel.Handlers;
using JeffOps.Authentication.SharedKernel.Validation;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.SharedKernel.DependencyInjection;

/// <summary>
/// Explicit, scan-free registration of handlers, validators and decorators (docs/DESIGN.md §6.1).
/// Each module's <c>AddJeffOps{Module}()</c> registers its slices one by one, so every registration is visible in review.
/// </summary>
public static class HandlerServiceCollectionExtensions
{
    private static readonly Type[] HandlerInterfaces =
    [
        typeof(ICommandHandler<>),
        typeof(ICommandHandler<,>),
        typeof(IQueryHandler<,>),
    ];

    /// <summary>
    /// Registers <typeparamref name="THandler"/> as scoped under every handler interface it implements.
    /// </summary>
    /// <exception cref="ArgumentException"><typeparamref name="THandler"/> implements no handler interface.</exception>
    public static IServiceCollection AddHandler<THandler>(this IServiceCollection services)
        where THandler : class
    {
        ArgumentNullException.ThrowIfNull(services);
        return services.AddClosedImplementations(typeof(THandler), HandlerInterfaces);
    }

    /// <summary>
    /// Registers <typeparamref name="TValidator"/> as scoped under every <see cref="IValidator{T}"/> it implements.
    /// </summary>
    public static IServiceCollection AddValidator<TValidator>(this IServiceCollection services)
        where TValidator : class
    {
        ArgumentNullException.ThrowIfNull(services);
        return services.AddClosedImplementations(typeof(TValidator), [typeof(IValidator<>)]);
    }

    /// <summary>
    /// Registers <typeparamref name="THandler"/> as scoped under every <see cref="IDomainEventHandler{TEvent}"/> it implements.
    /// </summary>
    public static IServiceCollection AddDomainEventHandler<THandler>(this IServiceCollection services)
        where THandler : class
    {
        ArgumentNullException.ThrowIfNull(services);
        return services.AddClosedImplementations(typeof(THandler), [typeof(IDomainEventHandler<>)]);
    }

    /// <summary>
    /// Registers the default <see cref="IDomainEventDispatcher"/>.
    /// </summary>
    public static IServiceCollection AddDomainEventDispatcher(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddScoped<IDomainEventDispatcher, DomainEventDispatcher>();
        return services;
    }

    /// <summary>
    /// Wraps every handler registered so far in a decorator that runs its <see cref="IValidator{T}"/>s first. Call after all
    /// handlers of the module are registered. Handlers already wrapped by an earlier call (another module's) are skipped, so
    /// every module can call it.
    /// </summary>
    public static IServiceCollection AddHandlerValidation(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        var alreadyValidated = services
            .Select(descriptor => descriptor.ImplementationInstance)
            .OfType<ValidatedService>()
            .Select(marker => marker.ServiceType)
            .ToHashSet();

        var toValidate = services
            .Where(IsHandler)
            .Select(descriptor => descriptor.ServiceType)
            .Where(serviceType => !alreadyValidated.Contains(serviceType))
            .ToHashSet();

        bool ShouldDecorate(ServiceDescriptor descriptor) => toValidate.Contains(descriptor.ServiceType);

        services
            .DecorateOpenGeneric(typeof(ICommandHandler<>), typeof(ValidatingCommandHandler<>), ShouldDecorate)
            .DecorateOpenGeneric(typeof(ICommandHandler<,>), typeof(ValidatingCommandHandler<,>), ShouldDecorate)
            .DecorateOpenGeneric(typeof(IQueryHandler<,>), typeof(ValidatingQueryHandler<,>), ShouldDecorate);

        foreach (var serviceType in toValidate)
        {
            services.AddSingleton(new ValidatedService(serviceType));
        }

        return services;
    }

    private static bool IsHandler(ServiceDescriptor descriptor) =>
        !descriptor.IsKeyedService
        && descriptor.ServiceType.IsGenericType
        && HandlerInterfaces.Contains(descriptor.ServiceType.GetGenericTypeDefinition());

    /// <summary>
    /// Replaces every registration of a closed <paramref name="openServiceType"/> with
    /// <paramref name="openDecoratorType"/> closed over the same type arguments, wrapping the original.
    /// The decorator's constructor takes the inner service plus any other registered dependencies.
    /// Keyed registrations are left alone.
    /// </summary>
    public static IServiceCollection DecorateOpenGeneric(
        this IServiceCollection services,
        Type openServiceType,
        Type openDecoratorType,
        Func<ServiceDescriptor, bool>? filter = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(openServiceType);
        ArgumentNullException.ThrowIfNull(openDecoratorType);

        var decorated = new List<DecoratedService>();

        for (var i = 0; i < services.Count; i++)
        {
            var original = services[i];
            if (original.IsKeyedService
                || !original.ServiceType.IsGenericType
                || original.ServiceType.GetGenericTypeDefinition() != openServiceType
                || (filter is not null && !filter(original)))
            {
                continue;
            }

            var decoratorType = openDecoratorType.MakeGenericType(original.ServiceType.GenericTypeArguments);
            services[i] = ServiceDescriptor.Describe(
                original.ServiceType,
                provider => ActivatorUtilities.CreateInstance(provider, decoratorType, CreateInner(provider, original)),
                original.Lifetime);

            if (original.ImplementationType is { } implementationType)
            {
                decorated.Add(new DecoratedService(original.ServiceType, implementationType));
            }
        }

        foreach (var record in decorated)
        {
            services.AddSingleton(record);
        }

        return services;
    }

    private static object CreateInner(IServiceProvider provider, ServiceDescriptor original) =>
        original.ImplementationInstance
        ?? original.ImplementationFactory?.Invoke(provider)
        ?? ActivatorUtilities.CreateInstance(provider, original.ImplementationType!);

    private static IServiceCollection AddClosedImplementations(this IServiceCollection services, Type implementationType, Type[] openInterfaces)
    {
        if (implementationType.IsAbstract || implementationType.IsGenericTypeDefinition)
        {
            throw new ArgumentException($"{implementationType} must be a concrete, closed type.", nameof(implementationType));
        }

        var serviceTypes = implementationType.GetInterfaces()
            .Where(type => type.IsGenericType && openInterfaces.Contains(type.GetGenericTypeDefinition()))
            .ToList();

        if (serviceTypes.Count == 0)
        {
            throw new ArgumentException(
                $"{implementationType} implements none of: {string.Join(", ", openInterfaces.Select(type => type.Name))}.",
                nameof(implementationType));
        }

        foreach (var serviceType in serviceTypes)
        {
            services.AddScoped(serviceType, implementationType);
        }

        return services;
    }
}

/// <summary>Marks a handler service type already wrapped by the validation decorator.</summary>
internal sealed record ValidatedService(Type ServiceType);

/// <summary>
/// Records the original implementation behind a decorated registration, so tooling (and the architecture tests)
/// can still see which concrete handler a service resolves to.
/// </summary>
/// <param name="ServiceType">The handler interface that was decorated.</param>
/// <param name="ImplementationType">The concrete handler behind the decorators.</param>
public sealed record DecoratedService(Type ServiceType, Type ImplementationType);

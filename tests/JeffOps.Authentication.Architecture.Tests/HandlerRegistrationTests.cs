using System.Reflection;
using JeffOps.Authentication.Architecture.Tests.Infrastructure;
using JeffOps.Authentication.SharedKernel.DependencyInjection;
using JeffOps.Authentication.SharedKernel.Handlers;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Architecture.Tests;

/// <summary>
/// Handlers are registered explicitly, not by assembly scanning (docs/DESIGN.md §6.1). This test catches the
/// failure mode of that choice: a slice whose handler was written but never registered.
/// </summary>
public sealed class HandlerRegistrationTests
{
    private static readonly Type[] HandlerInterfaces =
    [
        typeof(ICommandHandler<>),
        typeof(ICommandHandler<,>),
        typeof(IQueryHandler<,>),
    ];

    [Fact]
    public void Every_handler_is_registered_by_its_module()
    {
        var services = new ServiceCollection();
        var configuration = new ConfigurationBuilder().Build();

        foreach (var register in ModuleRegistrations())
        {
            register.Invoke(null, register.GetParameters().Length == 1 ? [services] : [services, configuration]);
        }

        var registered = services
            .Select(descriptor => descriptor.ImplementationInstance is DecoratedService decorated
                ? decorated.ImplementationType
                : descriptor.ImplementationType)
            .OfType<Type>()
            .ToHashSet();

        Handlers()
            .Where(handler => !registered.Contains(handler))
            .Select(handler => handler.FullName)
            .ShouldBeEmpty("Register each handler in its module's AddJeffOps{Module}() with services.AddHandler<T>().");
    }

    /// <summary>Concrete handler implementations in the source assemblies, excluding decorators.</summary>
    private static IEnumerable<Type> Handlers() =>
        from assembly in Repository.SourceAssemblies
        from type in assembly.GetTypes()
        where type is { IsClass: true, IsAbstract: false, IsGenericTypeDefinition: false }
        let handlerInterfaces = type.GetInterfaces().Where(IsHandlerInterface).ToList()
        where handlerInterfaces.Count > 0 && !IsDecorator(type, handlerInterfaces)
        select type;

    /// <summary>
    /// Public static <c>AddJeffOps*</c> extension methods taking <see cref="IServiceCollection"/> and optionally
    /// <see cref="IConfiguration"/>: the entry points hosts call (docs/DESIGN.md §6.4).
    /// </summary>
    private static IEnumerable<MethodInfo> ModuleRegistrations() =>
        from assembly in Repository.SourceAssemblies
        from type in assembly.GetExportedTypes()
        where type is { IsAbstract: true, IsSealed: true }
        from method in type.GetMethods(BindingFlags.Public | BindingFlags.Static)
        where method.Name.StartsWith("AddJeffOps", StringComparison.Ordinal) && !method.IsGenericMethodDefinition
        let parameters = method.GetParameters().Select(parameter => parameter.ParameterType).ToArray()
        where parameters is [var first] && first == typeof(IServiceCollection)
            || parameters is [var head, var second] && head == typeof(IServiceCollection) && second == typeof(IConfiguration)
        select method;

    private static bool IsHandlerInterface(Type type) =>
        type.IsGenericType && HandlerInterfaces.Contains(type.GetGenericTypeDefinition());

    private static bool IsDecorator(Type type, List<Type> handlerInterfaces) =>
        type.GetConstructors().Any(constructor =>
            constructor.GetParameters().Any(parameter => handlerInterfaces.Contains(parameter.ParameterType)));
}

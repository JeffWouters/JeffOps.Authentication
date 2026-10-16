using JeffOps.Authentication.Abstractions.Access;
using JeffOps.Authentication.Abstractions.Claims;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace JeffOps.Entitlements;

/// <summary>
/// Whether the caller's tenant (or organization) has bought a feature. The host's billing or licensing system answers; the
/// libraries only ask (docs/DESIGN.md §11.2, step 8).
/// </summary>
public interface IEntitlementChecker
{
    /// <summary>Whether <paramref name="access"/> is entitled to <paramref name="entitlement"/>, for example <c>reports.export</c>.</summary>
    ValueTask<bool> HasAsync(string entitlement, AccessContext access, CancellationToken cancellationToken);
}

/// <summary>The default: everything is allowed, so an endpoint marked with an entitlement works before billing is wired up.</summary>
public sealed class AllowAllEntitlements : IEntitlementChecker
{
    /// <inheritdoc />
    public ValueTask<bool> HasAsync(string entitlement, AccessContext access, CancellationToken cancellationToken) => ValueTask.FromResult(true);
}

/// <summary>Registration and route conventions for entitlement checks.</summary>
public static class EntitlementExtensions
{
    /// <summary>The <c>code</c> of the 402 problem answered when an entitlement is missing.</summary>
    public const string EntitlementRequired = "entitlement_required";

    /// <summary>
    /// Adds entitlement checks with <typeparamref name="TChecker"/>, or with <see cref="AllowAllEntitlements"/> when none is
    /// given. Call it once; a later call with a checker replaces the earlier one.
    /// </summary>
    public static IServiceCollection AddJeffOpsEntitlements<TChecker>(this IServiceCollection services)
        where TChecker : class, IEntitlementChecker
    {
        ArgumentNullException.ThrowIfNull(services);
        services.RemoveAll<IEntitlementChecker>();
        services.AddScoped<IEntitlementChecker, TChecker>();
        services.TryAddSingleton(ClaimNames.Default);
        return services;
    }

    /// <summary>Adds entitlement checks that allow everything (<see cref="AllowAllEntitlements"/>).</summary>
    public static IServiceCollection AddJeffOpsEntitlements(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddScoped<IEntitlementChecker, AllowAllEntitlements>();
        services.TryAddSingleton(ClaimNames.Default);
        return services;
    }

    /// <summary>
    /// Requires <paramref name="entitlement"/> for the endpoint(s). A caller without it gets <c>402 Payment Required</c> with
    /// problem code <see cref="EntitlementRequired"/> and the entitlement's name, so the client can offer an upgrade.
    /// Authentication and authorization run first; this only narrows.
    /// </summary>
    public static TBuilder RequireEntitlement<TBuilder>(this TBuilder builder, string entitlement)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(entitlement);
        builder.AddEndpointFilter(async (context, next) =>
        {
            var http = context.HttpContext;
            var access = http.RequestServices.GetService<IAccessContextAccessor>()?.GetAccessContext()
                ?? AccessContextReader.Read(http.User, http.RequestServices.GetService<ClaimNames>() ?? ClaimNames.Default);
            var checker = http.RequestServices.GetService<IEntitlementChecker>()
                ?? throw new InvalidOperationException("Call AddJeffOpsEntitlements() to use RequireEntitlement.");

            if (await checker.HasAsync(entitlement, access, http.RequestAborted).ConfigureAwait(false))
            {
                return await next(context).ConfigureAwait(false);
            }

            return TypedResults.Problem(
                detail: $"Your plan doesn't include {entitlement}.",
                statusCode: StatusCodes.Status402PaymentRequired,
                extensions: new Dictionary<string, object?> { ["code"] = EntitlementRequired, ["entitlement"] = entitlement });
        });
        return builder;
    }
}

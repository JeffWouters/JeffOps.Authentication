using JeffOps.Authentication.UI.Components;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.UI;

/// <summary>Registers and maps the hosted login UI.</summary>
public static class UiServiceCollectionExtensions
{
    /// <summary>Adds the hosted login UI (Razor components, static server rendering).</summary>
    public static IServiceCollection AddJeffOpsAuthenticationUI(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.AddRazorComponents();
        return services;
    }

    /// <summary>
    /// Maps the login page at <c>account/login</c>. The host must call <c>UseAntiforgery()</c> (Razor component endpoints
    /// require it) and serve static web assets (<c>MapStaticAssets()</c>) for the stylesheet.
    /// </summary>
    public static IEndpointRouteBuilder MapJeffOpsAuthenticationUI(this IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        endpoints.MapRazorComponents<LoginApp>();
        return endpoints;
    }
}

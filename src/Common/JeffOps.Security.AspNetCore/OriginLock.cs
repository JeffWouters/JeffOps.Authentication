using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace JeffOps.Security.AspNetCore;

/// <summary>
/// Refuses requests that didn't come through the expected edge (for example an Azure Front Door profile, which stamps
/// <c>X-Azure-FDID</c>). Bound from <see cref="SectionName"/>; off while <see cref="ExpectedValue"/> is unset.
/// </summary>
public sealed class OriginLockOptions
{
    public const string SectionName = "JeffOps:OriginLock";

    public string HeaderName { get; set; } = "X-Azure-FDID";

    /// <summary>The value the edge stamps. Unset disables the lock.</summary>
    public string? ExpectedValue { get; set; }

    /// <summary>Paths reachable without the header, for platform health probes.</summary>
    public IList<string> ExemptPaths { get; } = ["/health", "/alive"];
}

public static class OriginLockExtensions
{
    /// <summary>Answers 403 to any request without the expected edge header. Register first in the pipeline.</summary>
    public static IApplicationBuilder UseJeffOpsOriginLock(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var options = app.ApplicationServices.GetService<IOptions<OriginLockOptions>>()?.Value ?? new OriginLockOptions();
        if (string.IsNullOrWhiteSpace(options.ExpectedValue))
        {
            return app;
        }

        var exempt = options.ExemptPaths.Select(path => new PathString(path)).ToArray();
        return app.Use(async (context, next) =>
        {
            if (Allows(options, exempt, context.Request.Path, context.Request.Headers[options.HeaderName].ToString()))
            {
                await next(context).ConfigureAwait(false);
                return;
            }

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
        });
    }

    /// <remarks>Repeated headers join with a comma, so a request carrying two values never matches.</remarks>
    internal static bool Allows(OriginLockOptions options, IReadOnlyList<PathString> exempt, PathString path, string? headerValue) =>
        exempt.Any(candidate => path.Equals(candidate, StringComparison.OrdinalIgnoreCase))
        || (!string.IsNullOrWhiteSpace(headerValue)
            && string.Equals(headerValue.Trim(), options.ExpectedValue!.Trim(), StringComparison.OrdinalIgnoreCase));
}

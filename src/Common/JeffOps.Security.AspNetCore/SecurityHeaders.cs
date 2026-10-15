using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace JeffOps.Security.AspNetCore;

/// <summary>
/// Response security headers. Bound from <see cref="SectionName"/>. Defaults suit a JSON API: nothing may be framed,
/// sniffed, or loaded by a page (docs/DESIGN.md §16).
/// </summary>
public sealed class SecurityHeadersOptions
{
    public const string SectionName = "JeffOps:SecurityHeaders";

    public string ContentSecurityPolicy { get; set; } = "default-src 'none'; frame-ancestors 'none'";

    public string ReferrerPolicy { get; set; } = "no-referrer";

    public string FrameOptions { get; set; } = "DENY";

    public string CrossOriginOpenerPolicy { get; set; } = "same-origin";

    /// <summary>Sent on HTTPS responses only.</summary>
    public TimeSpan StrictTransportSecurityMaxAge { get; set; } = TimeSpan.FromDays(365);

    public bool StrictTransportSecurityIncludeSubDomains { get; set; } = true;
}

public static class SecurityHeadersApplicationBuilderExtensions
{
    /// <summary>Adds the security headers to every response. Register early, before endpoints write responses.</summary>
    public static IApplicationBuilder UseJeffOpsSecurityHeaders(this IApplicationBuilder app)
    {
        ArgumentNullException.ThrowIfNull(app);

        var options = app.ApplicationServices.GetService<IOptions<SecurityHeadersOptions>>()?.Value ?? new SecurityHeadersOptions();
        var hsts = $"max-age={(long)options.StrictTransportSecurityMaxAge.TotalSeconds}"
            + (options.StrictTransportSecurityIncludeSubDomains ? "; includeSubDomains" : string.Empty);

        return app.Use(async (context, next) =>
        {
            var headers = context.Response.Headers;
            headers.XContentTypeOptions = "nosniff";
            headers.XFrameOptions = options.FrameOptions;
            headers["Referrer-Policy"] = options.ReferrerPolicy;
            headers.ContentSecurityPolicy = options.ContentSecurityPolicy;
            headers["Cross-Origin-Opener-Policy"] = options.CrossOriginOpenerPolicy;
            if (context.Request.IsHttps)
            {
                headers.StrictTransportSecurity = hsts;
            }

            await next(context).ConfigureAwait(false);
        });
    }
}

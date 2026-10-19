using System.Globalization;
using JeffOps.Authentication.Abstractions.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.LocalAccounts.Endpoints;

/// <summary>
/// Rate limits of the local-account endpoints (docs/DESIGN.md D28, <see cref="RateLimitOptions"/>): sign-in attempts per
/// client address and per account, so passwords can't be sprayed across accounts nor the server kept busy hashing; and
/// requests that send mail per address and per recipient, so nobody's inbox can be flooded through this server.
/// </summary>
internal static class LocalAccountRateLimits
{
    /// <summary>Counts a sign-in attempt: per client address, and per account when the form names one.</summary>
    public static RouteHandlerBuilder SignInLimited(this RouteHandlerBuilder builder, Func<HttpContext, IResult>? whenLimited = null) =>
        builder.AddEndpointFilter(async (context, next) => await CheckAsync(context, mail: false, whenLimited).ConfigureAwait(false) ?? await next(context).ConfigureAwait(false));

    /// <summary>Counts a request that sends mail: per client address, and per recipient when the request names one.</summary>
    public static RouteHandlerBuilder MailLimited(this RouteHandlerBuilder builder) =>
        builder.AddEndpointFilter(async (context, next) => await CheckAsync(context, mail: true, whenLimited: null).ConfigureAwait(false) ?? await next(context).ConfigureAwait(false));

    private static async ValueTask<IResult?> CheckAsync(EndpointFilterInvocationContext context, bool mail, Func<HttpContext, IResult>? whenLimited)
    {
        var http = context.HttpContext;
        var options = http.RequestServices.GetRequiredService<IOptions<RateLimitOptions>>().Value;
        if (!options.Enabled)
        {
            return null;
        }

        var limiter = http.RequestServices.GetRequiredService<RequestRateLimiter>();
        var address = http.Connection.RemoteIpAddress?.ToString();
        var email = await EmailOfAsync(context).ConfigureAwait(false);
        TimeSpan wait;
        var allowed = mail
            ? limiter.TryAcquire(options.MailPerAddress, RateLimitPartitions.For("mail-address", address), out wait)
                && (email is null || limiter.TryAcquire(options.MailPerRecipient, RateLimitPartitions.For("mail-recipient", email), out wait))
            : limiter.TryAcquire(options.SignInPerAddress, RateLimitPartitions.For("signin-address", address), out wait)
                && (email is null || limiter.TryAcquire(options.SignInPerAccount, RateLimitPartitions.For("signin-account", email), out wait));
        if (allowed)
        {
            return null;
        }

        http.Response.Headers.RetryAfter = Math.Max(1, (int)Math.Ceiling(wait.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        return whenLimited?.Invoke(http) ?? Results.Text("Too many requests. Try again later.", "text/plain", statusCode: StatusCodes.Status429TooManyRequests);
    }

    /// <summary>The email address the request is about (JSON body or form), lowercased; null when it names none.</summary>
    private static async ValueTask<string?> EmailOfAsync(EndpointFilterInvocationContext context)
    {
        var email = context.Arguments.OfType<RegisterRequest>().FirstOrDefault()?.Email
            ?? context.Arguments.OfType<EmailRequest>().FirstOrDefault()?.Email;
        if (email is null && context.HttpContext.Request.HasFormContentType)
        {
            email = (await context.HttpContext.Request.ReadFormAsync(context.HttpContext.RequestAborted).ConfigureAwait(false))["email"].ToString();
        }

        return string.IsNullOrWhiteSpace(email) ? null : email.Trim().ToLowerInvariant();
    }
}

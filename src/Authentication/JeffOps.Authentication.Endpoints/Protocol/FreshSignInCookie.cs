using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Endpoints.Protocol;

/// <summary>
/// Remembers that one authorize request sent the user to sign in again (<c>prompt=login</c>, <c>max_age</c>): a
/// Data-Protected, HttpOnly cookie naming that request (a hash of the URL it comes back to) and the time the new sign-in
/// must follow. Coming back to exactly that URL with a sign-in after that time satisfies <c>prompt=login</c> and
/// <c>max_age</c> for that request only. A pushed request (PAR) keeps those parameters however the URL changes, so without
/// this the user would be asked to sign in forever; and the browser can't forge it to skip a re-authentication.
/// </summary>
internal static class FreshSignInCookie
{
    private const string Purpose = "JeffOps.Authentication.FreshSignIn.v1";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(30);

    public static void Set(HttpContext context, string returnUrl, DateTimeOffset after)
    {
        var value = string.Create(CultureInfo.InvariantCulture, $"{after.ToUnixTimeSeconds()}|{Hash(returnUrl)}");
        // A session cookie: the protected value expires by itself.
        context.Response.Cookies.Append(Name(context.Request), Protector(context).Protect(value, Lifetime), Options(context.Request, expires: null));
    }

    /// <summary>The time the sign-in must follow, when the current request is the one the cookie names; otherwise null.</summary>
    public static DateTimeOffset? Read(HttpContext context)
    {
        if (!context.Request.Cookies.TryGetValue(Name(context.Request), out var cookie) || string.IsNullOrEmpty(cookie))
        {
            return null;
        }

        string value;
        try
        {
            value = Protector(context).Unprotect(cookie);
        }
        catch (CryptographicException)
        {
            return null;
        }

        var separator = value.IndexOf('|', StringComparison.Ordinal);
        return separator > 0
            && long.TryParse(value.AsSpan(0, separator), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
            && string.Equals(value[(separator + 1)..], Hash(context.Request.PathBase + context.Request.Path + context.Request.QueryString), StringComparison.Ordinal)
                ? DateTimeOffset.FromUnixTimeSeconds(seconds)
                : null;
    }

    public static void Clear(HttpContext context) =>
        context.Response.Cookies.Delete(Name(context.Request), Options(context.Request, DateTimeOffset.UnixEpoch));

    private static ITimeLimitedDataProtector Protector(HttpContext context) =>
        context.RequestServices.GetRequiredService<IDataProtectionProvider>().CreateProtector(Purpose).ToTimeLimitedDataProtector();

    private static string Hash(string url) => Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(url)));

    private static string Name(HttpRequest request) => request.IsHttps ? "__Host-jeffops-fresh" : "jeffops-fresh";

    private static CookieOptions Options(HttpRequest request, DateTimeOffset? expires) => new()
    {
        HttpOnly = true,
        Secure = request.IsHttps,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        Expires = expires,
        IsEssential = true,
    };
}

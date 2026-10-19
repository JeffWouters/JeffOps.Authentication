using System.Text.Json;
using JeffOps.Authentication.Application.Federation;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

namespace JeffOps.Authentication.Infrastructure.Server;

/// <summary>
/// The browser's pending link (<see cref="IPendingLinks"/>) in a Data-Protected, HttpOnly cookie: only this server can read or
/// forge it, it names one account and one login, and it expires with the link (ten minutes).
/// </summary>
internal sealed class CookiePendingLinks(IHttpContextAccessor accessor, IDataProtectionProvider dataProtection, TimeProvider time) : IPendingLinks
{
    private const string Purpose = "JeffOps.Authentication.PendingLink.v1";
    private readonly ITimeLimitedDataProtector _protector = dataProtection.CreateProtector(Purpose).ToTimeLimitedDataProtector();
    private PendingLink? _set;
    private bool _cleared;

    public void Set(PendingLink link)
    {
        ArgumentNullException.ThrowIfNull(link);
        _set = link;
        _cleared = false;
        if (accessor.HttpContext is { } http)
        {
            var value = _protector.Protect(JsonSerializer.Serialize(link), link.ExpiresAt);
            http.Response.Cookies.Append(CookieName(http.Request), value, Options(http.Request, link.ExpiresAt));
        }
    }

    public PendingLink? Current
    {
        get
        {
            if (_cleared)
            {
                return null;
            }

            if (_set is { } set)
            {
                return set.ExpiresAt > time.GetUtcNow() ? set : null;
            }

            if (accessor.HttpContext?.Request is not { } request || !request.Cookies.TryGetValue(CookieName(request), out var value) || string.IsNullOrEmpty(value))
            {
                return null;
            }

            try
            {
                var link = JsonSerializer.Deserialize<PendingLink>(_protector.Unprotect(value));
                return link is not null && link.ExpiresAt > time.GetUtcNow() ? link : null;
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                return null;
            }
            catch (JsonException)
            {
                return null;
            }
        }
    }

    public void Clear()
    {
        _set = null;
        _cleared = true;
        if (accessor.HttpContext is { } http)
        {
            http.Response.Cookies.Delete(CookieName(http.Request), Options(http.Request, DateTimeOffset.UnixEpoch));
        }
    }

    private static string CookieName(HttpRequest request) => request.IsHttps ? "__Host-jeffops-link" : "jeffops-link";

    private static CookieOptions Options(HttpRequest request, DateTimeOffset expires) => new()
    {
        HttpOnly = true,
        Secure = request.IsHttps,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        Expires = expires,
        IsEssential = true,
    };
}

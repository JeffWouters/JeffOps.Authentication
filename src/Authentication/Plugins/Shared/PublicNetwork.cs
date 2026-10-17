using System.Net;
using System.Net.Sockets;

namespace JeffOps.Authentication.Federation;

/// <summary>
/// Outbound connections to addresses tenants supply (their providers' metadata URLs): only to public addresses. The check
/// runs on every connection, after DNS resolution, so a host name that resolves (or later re-resolves) to a private,
/// loopback or link-local address can't make this server reach its own network (SSRF). Shared source: compiled into each
/// federation plug-in that fetches from tenant-supplied URLs.
/// </summary>
internal static class PublicNetwork
{
    /// <summary>A handler that connects only to public addresses and doesn't follow redirects.</summary>
    public static SocketsHttpHandler Handler() => new()
    {
        AllowAutoRedirect = false,
        ConnectTimeout = TimeSpan.FromSeconds(10),
        ConnectCallback = ConnectAsync,
    };

    /// <summary>The body as text, refusing (<see cref="InvalidOperationException"/>) anything larger than <paramref name="maxBytes"/>.</summary>
    public static async Task<string> ReadLimitedAsync(HttpResponseMessage response, int maxBytes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.Content.Headers.ContentLength > maxBytes)
        {
            throw new InvalidOperationException("The response is too large.");
        }

        var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        await using (stream.ConfigureAwait(false))
        {
            using var buffer = new MemoryStream();
            var chunk = new byte[16 * 1024];
            int read;
            while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
            {
                if (buffer.Length + read > maxBytes)
                {
                    throw new InvalidOperationException("The response is too large.");
                }

                buffer.Write(chunk, 0, read);
            }

            return System.Text.Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
        }
    }

    public static bool IsPublic(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Broadcast))
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return !(bytes[0] == 10
                || bytes[0] == 0
                || (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)   // carrier-grade NAT
                || (bytes[0] == 169 && bytes[1] == 254)                     // link-local, cloud metadata
                || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0)
                || bytes[0] >= 224);                                        // multicast and reserved
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = address.GetAddressBytes();
            return !(address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast
                || (bytes[0] & 0xFE) == 0xFC);                              // unique local fc00::/7
        }

        return false;
    }

    private static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken).ConfigureAwait(false);
        var allowed = addresses.Where(IsPublic).ToArray();
        if (allowed.Length == 0)
        {
            throw new HttpRequestException($"'{context.DnsEndPoint.Host}' does not resolve to a public address.");
        }

        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(allowed, context.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}

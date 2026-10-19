using System.Net;
using System.Net.Sockets;

namespace JeffOps.Authentication.Federation;

/// <summary>
/// Outbound connections to addresses tenants supply (their providers' metadata URLs): only to public addresses. The check
/// runs on every connection, after DNS resolution, so a host name that resolves (or later re-resolves) to a private,
/// loopback or link-local address can't make this server reach its own network (SSRF). Never through a proxy: the proxy
/// would make the connection, past the check. Shared source: compiled into each federation plug-in that fetches from
/// tenant-supplied URLs.
/// </summary>
internal static class PublicNetwork
{
    /// <summary>A handler that connects only to public addresses, directly (no proxy), and doesn't follow redirects.</summary>
    public static SocketsHttpHandler Handler() => new()
    {
        AllowAutoRedirect = false,
        UseProxy = false,
        ConnectTimeout = TimeSpan.FromSeconds(10),
        ConnectCallback = ConnectAsync,
    };

    /// <summary>How long reading a body may take (the client's timeout ends at the headers when they're read first).</summary>
    public static readonly TimeSpan BodyTimeout = TimeSpan.FromSeconds(10);

    /// <summary>
    /// The body as text, refusing (<see cref="InvalidOperationException"/>) anything larger than <paramref name="maxBytes"/>
    /// or slower than <see cref="BodyTimeout"/>.
    /// </summary>
    public static async Task<string> ReadLimitedAsync(HttpResponseMessage response, int maxBytes, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.Content.Headers.ContentLength > maxBytes)
        {
            throw new InvalidOperationException("The response is too large.");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(BodyTimeout);
        try
        {
            return await ReadAsync(response, maxBytes, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new InvalidOperationException("The response took too long.");
        }
    }

    private static async Task<string> ReadAsync(HttpResponseMessage response, int maxBytes, CancellationToken cancellationToken)
    {
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

    /// <summary>
    /// Whether <paramref name="address"/> is a public unicast address. IPv6 addresses that carry an IPv4 address (mapped,
    /// NAT64 <c>64:ff9b::/96</c>, 6to4 <c>2002::/16</c>) are judged by that IPv4 address; Teredo, local-use NAT64 and the
    /// other special-use ranges are refused.
    /// </summary>
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
                || (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0)      // IETF protocol assignments
                || (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2)      // documentation
                || (bytes[0] == 192 && bytes[1] == 88 && bytes[2] == 99)    // 6to4 relay anycast
                || (bytes[0] == 198 && (bytes[1] == 18 || bytes[1] == 19))  // benchmarking 198.18.0.0/15
                || (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100)   // documentation
                || (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113)    // documentation
                || bytes[0] >= 224);                                        // multicast and reserved
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = address.GetAddressBytes();
            if (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b && bytes.AsSpan(4, 8).IndexOfAnyExcept((byte)0) < 0)
            {
                return IsPublic(new IPAddress(bytes.AsSpan(12, 4)));      // NAT64 64:ff9b::/96
            }

            if (bytes[0] == 0x20 && bytes[1] == 0x02)
            {
                return IsPublic(new IPAddress(bytes.AsSpan(2, 4)));       // 6to4 2002::/16
            }

            return !(address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6Multicast || address.IsIPv6Teredo
                || (bytes[0] & 0xFE) == 0xFC                                // unique local fc00::/7
                || bytes.AsSpan(0, 12).IndexOfAnyExcept((byte)0) < 0       // IPv4-compatible ::/96
                || (bytes[0] == 0x00 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b) // other NAT64, such as local-use 64:ff9b:1::/48
                || (bytes[0] == 0x01 && bytes[1] == 0x00 && bytes.AsSpan(2, 6).IndexOfAnyExcept((byte)0) < 0) // discard 100::/64
                || (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)            // documentation 2001:db8::/32
                || (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x00 && bytes[3] < 0x02));           // IETF protocol assignments 2001::/23
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

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using JeffOps.Authentication.Federation.Saml;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace JeffOps.Authentication.Server.Tests;

/// <summary>How tenant SAML metadata is downloaded and trusted (security review M15, M16).</summary>
public sealed class SamlMetadataTests : IDisposable
{
    private const string EntityId = "https://idp.test/";
    private static readonly Uri MetadataUrl = new("https://idp.test/metadata");

    private readonly FakeTimeProvider _time = new(new DateTimeOffset(2026, 10, 19, 9, 0, 0, TimeSpan.Zero));
    private readonly X509Certificate2 _certificate;

    public SamlMetadataTests()
    {
        using var key = RSA.Create(2048);
        _certificate = new CertificateRequest("CN=IdP", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    [Fact]
    public async Task Metadata_is_trusted_only_for_the_url_and_entity_it_came_from_and_not_forever()
    {
        var metadata = new SamlMetadata(_time);
        var client = Client(metadata, new Server(_ => Ok(Xml())));
        var settings = Settings();
        (await client.RefreshAsync("tenant-x", settings, "any", TestContext.Current.CancellationToken)).ShouldBeTrue();
        metadata.For("tenant-x", settings).ShouldNotBeNull();

        // The administrator moves to another metadata URL (or to explicit certificates): the old certificates stop counting.
        metadata.For("tenant-x", Settings(url: new Uri("https://idp.test/new-metadata"))).ShouldBeNull();
        metadata.For("tenant-x", Settings(url: null)).ShouldBeNull();
        metadata.For("tenant-x", Settings(MetadataUrl, entityId: "https://other.test/")).ShouldBeNull();

        // Refreshing keeps failing: the last good copy is trusted up to MetadataMaxAge, not after.
        _time.Advance(settings.MetadataMaxAge);
        metadata.For("tenant-x", settings).ShouldNotBeNull();
        _time.Advance(TimeSpan.FromMinutes(1));
        metadata.For("tenant-x", settings).ShouldBeNull();
    }

    [Fact]
    public async Task Parallel_requests_share_one_download_and_a_failure_backs_off()
    {
        var gate = new TaskCompletionSource();
        var server = new Server(async _ =>
        {
            await gate.Task;
            return new HttpResponseMessage(HttpStatusCode.InternalServerError);
        });
        var client = Client(new SamlMetadata(_time), server);
        var settings = Settings();

        var waiting = Enumerable.Range(0, 20).Select(_ => client.EnsureAsync("tenant-x", settings, TestContext.Current.CancellationToken)).ToList();
        gate.SetResult();
        await Task.WhenAll(waiting);
        server.Requests.ShouldBe(1);

        // Right after a failure nobody can make it download again; a minute later it tries again.
        await client.EnsureAsync("tenant-x", settings, TestContext.Current.CancellationToken);
        server.Requests.ShouldBe(1);
        _time.Advance(SamlMetadataClient.RetryAfterFailure);
        await client.EnsureAsync("tenant-x", settings, TestContext.Current.CancellationToken);
        server.Requests.ShouldBe(2);
    }

    [Fact]
    public async Task An_endless_metadata_document_is_refused_without_reading_it_all()
    {
        var metadata = new SamlMetadata(_time);
        var client = Client(metadata, new Server(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new Endless()) }));

        (await client.RefreshAsync("tenant-x", Settings(), "any", TestContext.Current.CancellationToken)).ShouldBeFalse();
        metadata.For("tenant-x", Settings()).ShouldBeNull();
    }

    public void Dispose() => _certificate.Dispose();

    private static SamlProviderOptions Settings() => Settings(MetadataUrl);

    private static SamlProviderOptions Settings(Uri? url, string entityId = EntityId) => new() { IdpEntityId = entityId, IdpMetadataUrl = url };

    private SamlMetadataClient Client(SamlMetadata metadata, Server server) =>
        new(metadata, new Factory(server), _time, NullLogger<SamlMetadataClient>.Instance);

    private static HttpResponseMessage Ok(string xml) =>
        new(HttpStatusCode.OK) { Content = new StringContent(xml, Encoding.UTF8, "application/samlmetadata+xml") };

    private string Xml() => $"""
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{EntityId}">
          <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:KeyDescriptor use="signing">
              <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{Convert.ToBase64String(_certificate.RawData)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
            </md:KeyDescriptor>
            <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/sso"/>
          </md:IDPSSODescriptor>
        </md:EntityDescriptor>
        """;

    private sealed class Server(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        private int _requests;

        public Server(Func<HttpRequestMessage, HttpResponseMessage> respond)
            : this(request => Task.FromResult(respond(request)))
        {
        }

        public int Requests => Volatile.Read(ref _requests);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _requests);
            return respond(request);
        }
    }

    private sealed class Factory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    /// <summary>A body that never ends.</summary>
    private sealed class Endless : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => 0; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            Array.Fill(buffer, (byte)' ', offset, count);
            return count;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

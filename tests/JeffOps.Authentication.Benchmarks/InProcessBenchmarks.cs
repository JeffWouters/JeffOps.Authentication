using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using JeffOps.Authentication.Abstractions.Dpop;
using JeffOps.Authentication.Enterprise.Application;
using JeffOps.Authorization.AspNetCore.DependencyInjection;
using JeffOps.Authorization.AspNetCore.Evaluation;
using JeffOps.Authorization.Contracts;
using JeffOps.Authorization.Domain.Decisions;
using JeffOps.Authorization.Domain.Policies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Benchmarks;

/// <summary>A permission decision in a resource service, with the role and policy data already cached (every API request).</summary>
[MemoryDiagnoser]
public class AuthorizationDecisionBenchmarks
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private ServiceProvider _provider = null!;
    private AsyncServiceScope _scope;
    private IAuthorizer _authorizer = null!;

    [Params(0, 10)]
    public int Policies { get; set; }

    [GlobalSetup]
    public async Task SetupAsync()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IAuthorizationDataSource>(new Source(Policies));
        services.AddJeffOpsPermissionAuthorization(new ConfigurationBuilder().Build());
        _provider = services.BuildServiceProvider();
        _scope = _provider.CreateAsyncScope();

        var user = Guid.NewGuid();
        _provider.GetRequiredService<IHttpContextAccessor>().HttpContext = new DefaultHttpContext
        {
            RequestServices = _scope.ServiceProvider,
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", user.ToString()), new Claim("tid", Tenant.ToString()), new Claim("lvl", "Tenant"), new Claim("amr", "pwd")], "Bearer")),
        };
        _authorizer = _scope.ServiceProvider.GetRequiredService<IAuthorizer>();
        await _authorizer.AuthorizeAsync(new AuthorizationRequest("orders.read"));   // warm the caches
    }

    [GlobalCleanup]
    public async Task CleanupAsync()
    {
        await _scope.DisposeAsync();
        await _provider.DisposeAsync();
    }

    [Benchmark]
    public Task<AuthorizationDecision> Allowed() => _authorizer.AuthorizeAsync(new AuthorizationRequest("orders.read"));

    [Benchmark]
    public Task<AuthorizationDecision> Denied() => _authorizer.AuthorizeAsync(new AuthorizationRequest("orders.delete"));

    private sealed class Source(int policies) : IAuthorizationDataSource
    {
        private static readonly Guid Reader = Guid.NewGuid();

        public Task<IReadOnlyList<UserAssignmentDto>> GetUserAssignmentsAsync(Guid userId, Guid tenantId, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<UserAssignmentDto>>([new UserAssignmentDto(Reader, "tenant", null, null)]);

        public Task<IReadOnlyDictionary<Guid, string[]>> GetRolePermissionsAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyDictionary<Guid, string[]>>(
                Enumerable.Range(0, 50).ToDictionary(_ => Guid.NewGuid(), index => new[] { $"area{index}.read", $"area{index}.write" })
                    .Append(KeyValuePair.Create(Reader, new[] { "orders.read", "orders.list", "reports.*" }))
                    .ToDictionary(pair => pair.Key, pair => pair.Value));

        public Task<IReadOnlyList<AttributePolicyDto>> GetPoliciesAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<AttributePolicyDto>>([.. Enumerable.Range(0, policies).Select(index => new AttributePolicyDto(
                Guid.NewGuid(), $"policy-{index}", null, index % 2 == 0 ? "orders.read" : "reports.read", null, PolicyEffect.Deny,
                """{"eq":["subject.email","blocked@example.com"]}""", index, true))]);

        public Task<IReadOnlyList<ScopeDto>> GetScopesAsync(CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<ScopeDto>>([new("platform", "Platform", null, null, true), new("tenant", "Tenant", null, "platform", true)]);
    }
}

/// <summary>A DPoP proof check (every request with a DPoP-bound token, and every DPoP token request).</summary>
[MemoryDiagnoser]
public class DpopProofBenchmarks
{
    private static readonly Uri Url = new("https://api.example.com/orders");
    private string _proof = null!;
    private DateTimeOffset _now;

    [GlobalSetup]
    public void Setup()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var parameters = key.ExportParameters(false);
        var header = new { typ = "dpop+jwt", alg = "ES256", jwk = new { kty = "EC", crv = "P-256", x = DpopProofValidator.Base64Url(parameters.Q.X!), y = DpopProofValidator.Base64Url(parameters.Q.Y!) } };
        _now = TimeProvider.System.GetUtcNow();
        var payload = new { jti = Guid.NewGuid().ToString("N"), htm = "GET", htu = Url.AbsoluteUri, iat = _now.ToUnixTimeSeconds() };
        var input = $"{DpopProofValidator.Base64Url(JsonSerializer.SerializeToUtf8Bytes(header))}.{DpopProofValidator.Base64Url(JsonSerializer.SerializeToUtf8Bytes(payload))}";
        var signature = key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256);
        _proof = $"{input}.{DpopProofValidator.Base64Url(signature)}";
    }

    [Benchmark]
    public DpopProof? Validate() => DpopProofValidator.Validate(_proof, "GET", Url, _now, TimeSpan.FromMinutes(5)).Proof;

    /// <summary>What Validate spends on turning the JWK into a key object, which it does for every proof.</summary>
    [Benchmark]
    public bool ImportKeyOnly()
    {
        using var key = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = _point });
        return key.KeySize == 256;
    }

    /// <summary>The signature check alone, with the key already imported.</summary>
    [Benchmark]
    public bool VerifyWithImportedKey() => _imported.VerifyData(_signed, _signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

    private ECPoint _point;
    private ECDsa _imported = null!;
    private byte[] _signed = null!;
    private byte[] _signature = null!;

    [GlobalSetup(Targets = [nameof(ImportKeyOnly), nameof(VerifyWithImportedKey)])]
    public void SetupKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        _point = key.ExportParameters(false).Q;
        _imported = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = _point });
        _signed = Encoding.ASCII.GetBytes("header.payload");
        _signature = key.SignData(_signed, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }
}

/// <summary>Parsing and translating SCIM filters (every SCIM list and search).</summary>
[MemoryDiagnoser]
public class ScimFilterBenchmarks
{
    [Benchmark]
    public object Simple() => ScimFilters.ForUsers(ScimFilterParser.Parse("""userName eq "jo@contoso.com" """).Value).Value;

    [Benchmark]
    public object Complex() => ScimFilters.ForGroups(ScimFilterParser.Parse(
        """(displayName sw "eng" or externalId eq "E-1") and not (members[value eq "8a3f6c1e-6a0b-4e5e-9c43-1d2b3c4d5e6f"]) and meta.lastModified gt "2026-01-01T00:00:00Z" """).Value).Value;
}

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JeffOps.Authentication.Abstractions.Dpop;
using JeffOps.Authentication.Abstractions.Replay;

namespace JeffOps.Authentication.Client.Tests;

/// <summary>Hostile and malformed proofs: each is refused with a reason, never with an exception.</summary>
public sealed class DpopProofHardeningTests
{
    private const string Url = "https://api.test/things";
    private static readonly Uri Target = new(Url);
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("ES256K")]
    [InlineData("RS512")]
    [InlineData("es256")]
    public void Algorithms_outside_the_allow_list_are_refused(string alg)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = Sign(EcHeader(key, alg: alg), Claims(), data => key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        Validate(proof).Error.ShouldBe("The DPoP proof's algorithm is not supported.");
    }

    [Fact]
    public void A_proof_must_declare_its_type_and_carry_only_a_public_key()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] Signer(byte[] data) => key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        Validate(Sign(EcHeader(key, typ: "JWT"), Claims(), Signer)).Error.ShouldBe("The DPoP proof must have typ dpop+jwt.");

        var withPrivate = EcHeader(key);
        ((Dictionary<string, object>)withPrivate["jwk"])["d"] = DpopProofValidator.Base64Url(key.ExportParameters(true).D!);
        Validate(Sign(withPrivate, Claims(), Signer)).Error.ShouldBe("The DPoP proof must carry a public jwk.");

        Validate(Sign(EcHeader(key), Claims(), Signer)).Proof.ShouldNotBeNull();
    }

    [Fact]
    public void A_key_seen_before_still_checks_every_signature()
    {
        // The validator keeps imported keys by thumbprint; a second proof with the same key must be checked in full.
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] Signer(byte[] data) => key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        Validate(Sign(EcHeader(key), Claims(), Signer)).Proof.ShouldNotBeNull();
        Validate(Sign(EcHeader(key), Claims(), Signer)).Proof.ShouldNotBeNull("the cached key verifies again");
        Validate(Sign(EcHeader(key), Claims(), data => other.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)))
            .Error.ShouldBe("The DPoP proof's signature is invalid.", "signed by another key, claiming the cached one");
        Validate(Sign(EcHeader(other), Claims(), Signer)).Error.ShouldBe("The DPoP proof's signature is invalid.", "another key never reuses the cached one");

        // Concurrent checks of one key never share an instance.
        Parallel.For(0, 200, _ => Validate(Sign(EcHeader(key), Claims(), Signer)).Proof.ShouldNotBeNull());
    }

    [Fact]
    public void The_curve_must_match_the_algorithm()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var proof = Sign(EcHeader(key, alg: "ES384"), Claims(), data => key.SignData(data, HashAlgorithmName.SHA384, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        Validate(proof).Error.ShouldBe("The DPoP proof's signature is invalid.");
    }

    [Theory]
    [InlineData("RS256")]
    [InlineData("PS256")]
    public void Rsa_keys_of_2048_bits_or_more_work(string alg)
    {
        using var key = RSA.Create(2048);
        var padding = alg == "PS256" ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;

        var (proof, error) = Validate(Sign(RsaHeader(key, alg), Claims(), data => key.SignData(data, HashAlgorithmName.SHA256, padding)));

        proof.ShouldNotBeNull(error);
    }

    [Fact]
    public void Small_rsa_keys_are_refused_even_when_padded_to_look_large()
    {
        using var key = RSA.Create(1024);
        byte[] Signer(byte[] data) => key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Validate(Sign(RsaHeader(key, "RS256"), Claims(), Signer)).Error.ShouldBe("The DPoP proof's signature is invalid.");

        // 1024 bits behind 128 zero bytes: 256 bytes long, still a 1024-bit key.
        var padded = RsaHeader(key, "RS256");
        var modulus = key.ExportParameters(false).Modulus!;
        ((Dictionary<string, object>)padded["jwk"])["n"] = DpopProofValidator.Base64Url([.. new byte[128], .. modulus]);
        Validate(Sign(padded, Claims(), Signer)).Error.ShouldBe("The DPoP proof's signature is invalid.");
    }

    [Fact]
    public void Out_of_range_and_malformed_values_are_refused_without_exceptions()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] Signer(byte[] data) => key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        var hugeIat = Claims();
        hugeIat["iat"] = long.MaxValue;
        Validate(Sign(EcHeader(key), hugeIat, Signer)).Error.ShouldBe("The DPoP proof is too old or from the future.");

        var negativeIat = Claims();
        negativeIat["iat"] = long.MinValue;
        Validate(Sign(EcHeader(key), negativeIat, Signer)).Error.ShouldBe("The DPoP proof is too old or from the future.");

        var longJti = Claims();
        longJti["jti"] = new string('x', DpopProofValidator.MaxJtiLength + 1);
        Validate(Sign(EcHeader(key), longJti, Signer)).Error.ShouldBe("The DPoP proof has no jti, or one that is too long.");

        // A lone surrogate escape: valid JSON, invalid UTF-16 text.
        var segment = DpopProofValidator.Base64Url(Encoding.UTF8.GetBytes("""{"typ":"\uD800","alg":"ES256"}"""));
        Validate($"{segment}.{segment}.AAAA").Error.ShouldNotBeNull();
    }

    [Fact]
    public void Mutated_proofs_never_pass_and_never_throw()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var original = Sign(EcHeader(key), Claims(), data => key.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        var originalSegments = Segments(original);
        const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.=+/ é\0";
        var random = new Random(9449);

        for (var round = 0; round < 3_000; round++)
        {
            var characters = original.ToCharArray().ToList();
            for (var edits = random.Next(1, 4); edits > 0; edits--)
            {
                var at = random.Next(characters.Count);
                switch (random.Next(3))
                {
                    case 0:
                        characters[at] = Alphabet[random.Next(Alphabet.Length)];
                        break;
                    case 1:
                        characters.RemoveAt(at);
                        break;
                    default:
                        characters.Insert(at, Alphabet[random.Next(Alphabet.Length)]);
                        break;
                }
            }

            var mutated = new string([.. characters]);
            var (proof, error) = Validate(mutated);

            // Base64url has spare bits in its last character, so a mutation may decode to the very same bytes; only such
            // proofs may pass.
            if (proof is not null)
            {
                Segments(mutated).ShouldBe(originalSegments, $"accepted a changed proof: {mutated}");
            }
            else
            {
                error.ShouldNotBeNullOrWhiteSpace();
            }
        }
    }

    [Fact]
    public void Random_json_in_every_position_is_refused_without_exceptions()
    {
        var random = new Random(7638);
        for (var round = 0; round < 2_000; round++)
        {
            var header = new Dictionary<string, object?>
            {
                ["typ"] = random.Next(4) == 0 ? RandomValue(random, 2) : "dpop+jwt",
                ["alg"] = random.Next(3) == 0 ? RandomValue(random, 2) : DpopProofValidator.Algorithms[random.Next(DpopProofValidator.Algorithms.Count)],
                ["jwk"] = random.Next(2) == 0
                    ? RandomValue(random, 3)
                    : new Dictionary<string, object?> { ["kty"] = random.Next(2) == 0 ? "EC" : "RSA", ["crv"] = RandomValue(random, 1), ["x"] = RandomValue(random, 1), ["y"] = RandomValue(random, 1), ["n"] = RandomValue(random, 1), ["e"] = RandomValue(random, 1) },
            };
            var payload = new Dictionary<string, object?>
            {
                ["jti"] = RandomValue(random, 1),
                ["htm"] = random.Next(2) == 0 ? "GET" : RandomValue(random, 1),
                ["htu"] = random.Next(2) == 0 ? Url : RandomValue(random, 1),
                ["iat"] = random.Next(2) == 0 ? Now.ToUnixTimeSeconds() : RandomValue(random, 1),
                ["ath"] = RandomValue(random, 1),
                ["nonce"] = RandomValue(random, 1),
            };
            var proof = $"{Encode(header)}.{Encode(payload)}.{DpopProofValidator.Base64Url(RandomNumberGenerator.GetBytes(random.Next(0, 600)))}";

            var (accepted, error) = Validate(proof);

            accepted.ShouldBeNull();
            error.ShouldNotBeNullOrWhiteSpace();
        }
    }

    [Fact]
    public async Task The_replay_cache_lets_each_value_through_once_and_stays_bounded()
    {
        var time = new Microsoft.Extensions.Time.Testing.FakeTimeProvider(Now);
        var cache = new MemoryReplayCache(time, capacity: 2);
        var ct = TestContext.Current.CancellationToken;

        (await cache.TryAddAsync("a", Now.AddMinutes(10), ct)).ShouldBeTrue();
        (await cache.TryAddAsync("a", Now.AddMinutes(10), ct)).ShouldBeFalse();
        (await cache.TryAddAsync("b", Now.AddMinutes(10), ct)).ShouldBeTrue();
        (await cache.TryAddAsync("c", Now.AddMinutes(10), ct)).ShouldBeFalse("full: refused rather than forgotten");

        time.Advance(TimeSpan.FromMinutes(11));
        (await cache.TryAddAsync("c", Now.AddMinutes(30), ct)).ShouldBeTrue("expired entries make room");
        (await cache.TryAddAsync("a", Now.AddMinutes(30), ct)).ShouldBeTrue("an expired key can be used again");
    }

    [Fact]
    public async Task The_replay_cache_admits_a_value_once_under_concurrency()
    {
        var cache = new MemoryReplayCache();

        var results = await Task.WhenAll(Enumerable.Range(0, 64).Select(_ =>
            Task.Run(async () => await cache.TryAddAsync("same", DateTimeOffset.UtcNow.AddMinutes(10), TestContext.Current.CancellationToken), TestContext.Current.CancellationToken)));

        results.Count(admitted => admitted).ShouldBe(1);
    }

    [Fact]
    public void Replay_keys_are_fixed_length_and_hide_the_value()
    {
        var key = ReplayKeys.For("dpop", new string('x', 10_000));

        key.ShouldStartWith("dpop:");
        key.Length.ShouldBe("dpop:".Length + 64);
        key.ShouldBe(key.ToLowerInvariant());
        ReplayKeys.For("saml", "same").ShouldNotBe(ReplayKeys.For("dpop", "same"));
    }

    // ---- Helpers --------------------------------------------------------------------------------------------------------

    private static (DpopProof? Proof, string? Error) Validate(string proof) => DpopProofValidator.Validate(proof, "GET", Target, Now, Window);

    private static Dictionary<string, object> EcHeader(ECDsa key, string alg = "ES256", string typ = "dpop+jwt")
    {
        var q = key.ExportParameters(false).Q;
        return new()
        {
            ["typ"] = typ,
            ["alg"] = alg,
            ["jwk"] = new Dictionary<string, object> { ["kty"] = "EC", ["crv"] = "P-256", ["x"] = DpopProofValidator.Base64Url(q.X!), ["y"] = DpopProofValidator.Base64Url(q.Y!) },
        };
    }

    private static Dictionary<string, object> RsaHeader(RSA key, string alg)
    {
        var parameters = key.ExportParameters(false);
        return new()
        {
            ["typ"] = "dpop+jwt",
            ["alg"] = alg,
            ["jwk"] = new Dictionary<string, object> { ["kty"] = "RSA", ["n"] = DpopProofValidator.Base64Url(parameters.Modulus!), ["e"] = DpopProofValidator.Base64Url(parameters.Exponent!) },
        };
    }

    private static Dictionary<string, object> Claims() => new()
    {
        ["jti"] = Guid.NewGuid().ToString("N"),
        ["htm"] = "GET",
        ["htu"] = Url,
        ["iat"] = Now.ToUnixTimeSeconds(),
    };

    private static string Sign(object header, object payload, Func<byte[], byte[]> signer)
    {
        var input = $"{Encode(header)}.{Encode(payload)}";
        return $"{input}.{DpopProofValidator.Base64Url(signer(Encoding.ASCII.GetBytes(input)))}";
    }

    private static string Encode(object value) => DpopProofValidator.Base64Url(JsonSerializer.SerializeToUtf8Bytes(value));

    /// <summary>The decoded bytes of each segment, or null where a segment doesn't decode.</summary>
    private static string?[] Segments(string proof) => [.. proof.Split('.').Select(segment =>
    {
        var base64 = segment.Replace('-', '+').Replace('_', '/');
        base64 = base64.PadRight(base64.Length + ((4 - (base64.Length % 4)) % 4), '=');
        var buffer = new byte[base64.Length];
        return Convert.TryFromBase64String(base64, buffer, out var written) ? Convert.ToHexString(buffer, 0, written) : null;
    })];

    private static object? RandomValue(Random random, int depth) => random.Next(depth > 0 ? 9 : 7) switch
    {
        0 => null,
        1 => random.Next(2) == 0,
        2 => random.NextInt64(long.MinValue, long.MaxValue),
        3 => random.NextDouble() * 1e300,
        4 => new string((char)random.Next(0, 0xFFFF), random.Next(0, 300)),
        5 => "",
        6 => DpopProofValidator.Base64Url(RandomNumberGenerator.GetBytes(random.Next(0, 600))),
        7 => Enumerable.Range(0, random.Next(0, 4)).Select(_ => RandomValue(random, depth - 1)).ToArray(),
        _ => Enumerable.Range(0, random.Next(0, 4)).ToDictionary(index => $"k{index}", _ => RandomValue(random, depth - 1)),
    };
}

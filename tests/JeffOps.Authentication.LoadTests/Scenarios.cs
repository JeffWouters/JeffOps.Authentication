using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JeffOps.Authentication.LoadTests;

/// <summary>
/// A workload: what each virtual user prepares once, and what it does in a loop. The runner measures the loop.
/// </summary>
internal abstract class Scenario
{
    public abstract string Name { get; }

    /// <summary>One virtual user's state, created before the clock starts.</summary>
    public abstract Task<object?> PrepareAsync(Stack stack, int user);

    /// <summary>One operation of a virtual user; throws on a failed one.</summary>
    public abstract Task RunAsync(Stack stack, object? state);

    /// <summary>Whether a warm-up may run the loop first (not when each operation uses up prepared state).</summary>
    public virtual bool WarmsUp => true;
}

internal static class Scenarios
{
    public static IReadOnlyList<Scenario> All { get; } =
    [
        new Plumbing(),
        new ClientCredentials(),
        new SignIn(),
        new Refresh(),
        new ApiAsUser(),
        new ApiAsNewUsers(),
        new ApiWithDpop(),
        new BffProxy(),
        new ScimProvisioning(),
    ];

    /// <summary>Every scenario, also those only run by name (not by <c>all</c>).</summary>
    public static IReadOnlyList<Scenario> Named { get; } = [.. All, new Mixed()];

    public static async Task EnsureOkAsync(HttpResponseMessage response, string what)
    {
        if (!response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.Redirect)
        {
            throw new InvalidOperationException($"{what}: {(int)response.StatusCode} {(await response.Content.ReadAsStringAsync())[..Math.Min(200, (int)(response.Content.Headers.ContentLength ?? 200))]}");
        }
    }

    /// <summary>An anonymous API call: what the in-process client and server cost by themselves.</summary>
    internal sealed class Plumbing : Scenario
    {
        public override string Name => "baseline-plumbing";

        public override Task<object?> PrepareAsync(Stack stack, int user) => Task.FromResult<object?>(null);

        public override async Task RunAsync(Stack stack, object? state)
        {
            using var response = await stack.Client.GetAsync(new Uri("https://api.test/api/ping"));
            await EnsureOkAsync(response, "ping");
        }
    }

    /// <summary>A service's client-credentials token.</summary>
    internal sealed class ClientCredentials : Scenario
    {
        public override string Name => "token-client-credentials";

        public override Task<object?> PrepareAsync(Stack stack, int user) => Task.FromResult<object?>(null);

        public override Task RunAsync(Stack stack, object? state) => stack.TokenAsync(new()
        {
            ["grant_type"] = "client_credentials", ["client_id"] = Stack.LoadClient, ["client_secret"] = Stack.LoadSecret, ["scope"] = "api",
        });
    }

    /// <summary>An interactive sign-in: the authorize endpoint (signed in) and the code exchange.</summary>
    internal sealed class SignIn : Scenario
    {
        public override string Name => "token-sign-in";

        public override async Task<object?> PrepareAsync(Stack stack, int user) => await stack.CreateUserAsync($"signin-{user}-{Guid.NewGuid():N}@contoso.com");

        public override Task RunAsync(Stack stack, object? state) => stack.SignInAsync((Guid)state!);
    }

    /// <summary>A signed-in session refreshing its tokens (what a BFF or app does every access-token lifetime).</summary>
    internal sealed class Refresh : Scenario
    {
        public override string Name => "token-refresh";

        public override async Task<object?> PrepareAsync(Stack stack, int user)
        {
            var account = await stack.CreateUserAsync($"refresh-{user}-{Guid.NewGuid():N}@contoso.com");
            return new StrongBox<string>((await stack.SignInAsync(account)).GetProperty("refresh_token").GetString()!);
        }

        public override async Task RunAsync(Stack stack, object? state)
        {
            var token = (StrongBox<string>)state!;
            var renewed = await stack.TokenAsync(new()
            {
                ["grant_type"] = "refresh_token", ["refresh_token"] = token.Value, ["client_id"] = Stack.BffClient, ["client_secret"] = Stack.BffSecret,
            });
            token.Value = renewed.GetProperty("refresh_token").GetString()!;
        }
    }

    /// <summary>A user's API calls: token validation and a permission decision from cached role data.</summary>
    internal sealed class ApiAsUser : Scenario
    {
        public override string Name => "api-user-decisions";

        public override async Task<object?> PrepareAsync(Stack stack, int user)
        {
            var account = await stack.CreateUserAsync($"api-{user}-{Guid.NewGuid():N}@contoso.com");
            return (await stack.SignInAsync(account)).GetProperty("access_token").GetString();
        }

        public override async Task RunAsync(Stack stack, object? state)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, Stack.ApiUrl);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", (string)state!);
            using var response = await stack.Client.SendAsync(request);
            await EnsureOkAsync(response, "api");
        }
    }

    /// <summary>
    /// API calls by ever new users (a large tenant's morning): every call is a decision-cache miss that reads the management
    /// service, and the caches fill with entries.
    /// </summary>
    internal sealed class ApiAsNewUsers : Scenario
    {
        private const int UsersPerVirtualUser = 150;

        public override string Name => "api-new-users";

        public override bool WarmsUp => false;

        public override async Task<object?> PrepareAsync(Stack stack, int user)
        {
            var tokens = new Queue<string>();
            for (var index = 0; index < UsersPerVirtualUser; index++)
            {
                var account = await stack.CreateUserAsync($"cold-{user}-{index}-{Guid.NewGuid():N}@contoso.com");
                tokens.Enqueue((await stack.SignInAsync(account)).GetProperty("access_token").GetString()!);
            }

            return tokens;
        }

        public override async Task RunAsync(Stack stack, object? state)
        {
            var tokens = (Queue<string>)state!;
            if (!tokens.TryDequeue(out var token))
            {
                throw new OperationCanceledException("out of users");
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, Stack.ApiUrl);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            using var response = await stack.Client.SendAsync(request);
            await EnsureOkAsync(response, "api");
        }
    }

    /// <summary>A service calling the API with a DPoP-bound token: a fresh proof per call, checked and recorded once.</summary>
    internal sealed class ApiWithDpop : Scenario
    {
        public override string Name => "api-dpop";

        public override async Task<object?> PrepareAsync(Stack stack, int user)
        {
            var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var token = await stack.TokenAsync(
                new() { ["grant_type"] = "client_credentials", ["client_id"] = Stack.DpopClient, ["client_secret"] = Stack.DpopSecret, ["scope"] = "api" },
                Proof(key, "POST", Stack.Issuer + "connect/token", null));
            return (key, token.GetProperty("access_token").GetString()!);
        }

        public override async Task RunAsync(Stack stack, object? state)
        {
            var (key, token) = ((ECDsa, string))state!;
            using var request = new HttpRequestMessage(HttpMethod.Get, Stack.ApiUrl);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("DPoP", token);
            request.Headers.Add("DPoP", Proof(key, "GET", Stack.ApiUrl, token));
            using var response = await stack.Client.SendAsync(request);
            await EnsureOkAsync(response, "api dpop");
        }

        private static string Proof(ECDsa key, string method, string url, string? accessToken)
        {
            var parameters = key.ExportParameters(false);
            var header = new { typ = "dpop+jwt", alg = "ES256", jwk = new { kty = "EC", crv = "P-256", x = Stack.Base64Url(parameters.Q.X!), y = Stack.Base64Url(parameters.Q.Y!) } };
            var payload = new Dictionary<string, object>
            {
                ["jti"] = Guid.NewGuid().ToString("N"),
                ["htm"] = method,
                ["htu"] = url,
                ["iat"] = TimeProvider.System.GetUtcNow().ToUnixTimeSeconds(),
            };
            if (accessToken is not null)
            {
                payload["ath"] = Stack.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));
            }

            var input = $"{Stack.Base64Url(JsonSerializer.SerializeToUtf8Bytes(header))}.{Stack.Base64Url(JsonSerializer.SerializeToUtf8Bytes(payload))}";
            return $"{input}.{Stack.Base64Url(key.SignData(Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))}";
        }
    }

    /// <summary>A browser's API calls through the BFF: the session cookie turned into a bearer and proxied.</summary>
    internal sealed class BffProxy : Scenario
    {
        public override string Name => "bff-proxy";

        public override async Task<object?> PrepareAsync(Stack stack, int user) =>
            await stack.BrowserAsync(await stack.CreateUserAsync($"bff-{user}-{Guid.NewGuid():N}@contoso.com"));

        public override async Task RunAsync(Stack stack, object? state)
        {
            using var response = await ((HttpClient)state!).GetAsync(new Uri("api/orders", UriKind.Relative));
            await EnsureOkAsync(response, "bff");
        }
    }

    /// <summary>An identity provider provisioning users: create, then update (the steady state of a provisioning cycle).</summary>
    internal sealed class ScimProvisioning : Scenario
    {
        public override string Name => "scim-provisioning";

        public override Task<object?> PrepareAsync(Stack stack, int user) => Task.FromResult<object?>(new StrongBox<int>(user * 1_000_000));

        public override async Task RunAsync(Stack stack, object? state)
        {
            var counter = (StrongBox<int>)state!;
            var index = counter.Value++;
            using var create = new HttpRequestMessage(HttpMethod.Post, "scim/v2/Users")
            {
                Content = new StringContent($$"""{"userName":"scim{{index}}@contoso.com","emails":[{"value":"scim{{index}}@contoso.com"}]}""", Encoding.UTF8, "application/scim+json"),
            };
            create.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", stack.ScimToken);
            using var created = await stack.Client.SendAsync(create);
            await EnsureOkAsync(created, "scim create");
            var id = JsonDocument.Parse(await created.Content.ReadAsStringAsync()).RootElement.GetProperty("id").GetString();

            using var patch = new HttpRequestMessage(HttpMethod.Patch, $"scim/v2/Users/{id}")
            {
                Content = new StringContent("""{"Operations":[{"op":"replace","path":"displayName","value":"Provisioned"}]}""", Encoding.UTF8, "application/scim+json"),
            };
            patch.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", stack.ScimToken);
            using var patched = await stack.Client.SendAsync(patch);
            await EnsureOkAsync(patched, "scim patch");
        }
    }

    private sealed class StrongBox<T>(T value)
    {
        public T Value { get; set; } = value;
    }
}

/// <summary>Runs a scenario with N virtual users for a duration after a warm-up, and measures it.</summary>
/// <summary>
/// A mix for long runs (soak): each virtual user cycles through API calls, BFF proxying, token requests, sign-ins and SCIM
/// writes, weighted roughly as a busy deployment would see them, so growth anywhere shows up in the timeline.
/// </summary>
internal sealed class Mixed : Scenario
{
    private static readonly Scenario[] Parts = [new Scenarios.ApiAsUser(), new Scenarios.BffProxy(), new Scenarios.ApiWithDpop(), new Scenarios.ClientCredentials(), new Scenarios.Refresh(), new Scenarios.SignIn(), new Scenarios.ScimProvisioning()];

    // Indexes into Parts: mostly API and BFF traffic, then tokens, then the rarer writes.
    private static readonly int[] Sequence = [0, 1, 0, 1, 2, 0, 1, 3, 0, 1, 4, 0, 1, 2, 0, 1, 5, 6];

    public override string Name => "mixed";

    public override async Task<object?> PrepareAsync(Stack stack, int user)
    {
        var states = new object?[Parts.Length];
        for (var part = 0; part < Parts.Length; part++)
        {
            states[part] = await Parts[part].PrepareAsync(stack, user);
        }

        return new State(states);
    }

    public override Task RunAsync(Stack stack, object? state)
    {
        var mixed = (State)state!;
        var part = Sequence[mixed.Next++ % Sequence.Length];
        return Parts[part].RunAsync(stack, mixed.States[part]);
    }

    private sealed class State(object?[] states)
    {
        public object?[] States { get; } = states;

        public int Next { get; set; }
    }
}

internal static class Runner
{
    public sealed record Result(string Scenario, int Users, TimeSpan Duration, int Operations, double PerSecond,
        (double P50, double P95, double P99, double Max) Latency, IReadOnlyDictionary<string, int> Errors, RuntimeSummary Runtime,
        IReadOnlyDictionary<string, long> RowsAdded);

    public static async Task<Result> RunAsync(Stack stack, Scenario scenario, int users, TimeSpan duration, TimeSpan warmUp)
    {
        var states = new object?[users];
        await Parallel.ForEachAsync(Enumerable.Range(0, users), new ParallelOptions { MaxDegreeOfParallelism = Math.Min(users, 16) },
            async (user, _) => states[user] = await scenario.PrepareAsync(stack, user));

        // Warm-up: caches, JIT and pools fill before anything is measured.
        if (scenario.WarmsUp)
        {
            await LoopAsync(stack, scenario, states, warmUp, null);
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        var rowsBefore = await stack.RowCountsAsync();
        using var sampler = new RuntimeSampler();
        var latencies = new LatencyRecorder();
        var clock = Stopwatch.StartNew();
        await LoopAsync(stack, scenario, states, duration, latencies);
        clock.Stop();
        var runtime = sampler.Stop();
        var rowsAfter = await stack.RowCountsAsync();
        return new Result(scenario.Name, users, clock.Elapsed, latencies.Count, latencies.Count / clock.Elapsed.TotalSeconds,
            latencies.Percentiles(), latencies.Errors, runtime,
            rowsAfter.ToDictionary(pair => pair.Key, pair => pair.Value - rowsBefore[pair.Key], StringComparer.Ordinal));
    }

    private static async Task LoopAsync(Stack stack, Scenario scenario, object?[] states, TimeSpan duration, LatencyRecorder? latencies)
    {
        using var stop = new CancellationTokenSource(duration);
        await Task.WhenAll(states.Select(state => Task.Run(async () =>
        {
            while (!stop.IsCancellationRequested)
            {
                var started = Stopwatch.GetTimestamp();
                try
                {
                    await scenario.RunAsync(stack, state);
                    latencies?.Record(Stopwatch.GetElapsedTime(started));
                }
                catch (OperationCanceledException exception) when (exception.Message == "out of users")
                {
                    return;
                }
                catch (Exception exception)
                {
                    latencies?.Error(exception.GetType().Name + ": " + exception.Message[..Math.Min(120, exception.Message.Length)]);
                }
            }
        })));
    }
}

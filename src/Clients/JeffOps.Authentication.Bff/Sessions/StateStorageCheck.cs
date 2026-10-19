using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace JeffOps.Authentication.Bff.Sessions;

/// <summary>
/// Outside Development, fails startup when the BFF's state would be lost or readable: sessions and exchanged tokens in the
/// in-process memory cache (replicas don't share it, a restart loses it), or a Data Protection key ring that isn't
/// persisted (<see cref="KeyManagementOptions.XmlRepository"/>) and encrypted at rest (<see cref="KeyManagementOptions.XmlEncryptor"/>).
/// </summary>
internal sealed class StateStorageCheck(IHostEnvironment environment, IDistributedCache cache, IOptions<KeyManagementOptions> keys) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (environment.IsDevelopment())
        {
            return Task.CompletedTask;
        }

        var problems = Problems(cache, keys.Value);
        return problems.Count == 0
            ? Task.CompletedTask
            : throw new InvalidOperationException(string.Join(" ", problems));
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    internal static List<string> Problems(IDistributedCache cache, KeyManagementOptions keys)
    {
        var problems = new List<string>();
        if (cache is MemoryDistributedCache)
        {
            problems.Add("The BFF needs a shared distributed cache (for example Redis) outside Development, not the in-process memory cache.");
        }

        if (keys.XmlRepository is null || keys.XmlEncryptor is null)
        {
            problems.Add("The BFF needs a persisted, encrypted Data Protection key ring outside Development: AddJeffOpsDataProtection with a KEK, and a key store such as PersistKeysToRedis.");
        }

        return problems;
    }
}

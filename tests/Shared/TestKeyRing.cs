using System.Collections.Concurrent;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;

namespace JeffOps.Authentication.Testing;

/// <summary>
/// A Data Protection key ring for in-process test hosts: kept in memory, unencrypted. The token server requires a persisted,
/// encrypted key ring outside Development; tests stand in for one with this. Never use it in a real host.
/// </summary>
internal static class TestKeyRing
{
    public static IServiceCollection AddTestKeyRing(this IServiceCollection services) =>
        services.Configure<KeyManagementOptions>(options =>
        {
            options.XmlRepository = new InMemoryXmlRepository();
            options.XmlEncryptor = new NullXmlEncryptor();
        });

    private sealed class InMemoryXmlRepository : IXmlRepository
    {
        private readonly ConcurrentQueue<XElement> _elements = new();

        public IReadOnlyCollection<XElement> GetAllElements() => [.. _elements.Select(element => new XElement(element))];

        public void StoreElement(XElement element, string friendlyName) => _elements.Enqueue(new XElement(element));
    }
}

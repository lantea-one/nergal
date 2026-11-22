using System.Reflection;
using Nergal.Core.Policy;
using Nergal.LocalTransport;
using Nergal.Nftables;
using Nergal.RemoteTransport;

namespace Nergal.Core.Tests;

/// <summary>Verifies CalVer release metadata stamped uniformly across shipped assemblies.</summary>
public sealed class ReleaseVersionTests
{
    private const string ExpectedCalVer = "2026.11.21.1";

    /// <summary>Core, compiler, and transport assemblies report exact CalVer <c>2026.11.21.1</c> metadata.</summary>
    [Fact]
    public void ShippedLibraries_ReportExpectedCalVerMetadata()
    {
        Assembly[] assemblies =
        [
            typeof(FilterPolicy).Assembly,
            typeof(NftFilterCompiler).Assembly,
            typeof(UnixControlClient).Assembly,
            typeof(TlsControlClient).Assembly,
        ];

        foreach (var assembly in assemblies)
        {
            var info = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            Assert.Equal(ExpectedCalVer, info);
            Assert.Equal(new Version(2026, 11, 21, 1), assembly.GetName().Version);
        }
    }
}

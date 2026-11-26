using System.Reflection;
using Nergal.Core.Policy;
using Nergal.LocalTransport;
using Nergal.Nftables;
using Nergal.RemoteTransport;

namespace Nergal.Core.Tests;

/// <summary>Verifies CalVer release metadata stamped uniformly across shipped assemblies.</summary>
public sealed class ReleaseVersionTests
{
    /// <summary>Core, compiler, and transport assemblies report the current project CalVer.</summary>
    [Fact]
    public void ShippedLibraries_ReportExpectedCalVerMetadata()
    {
        var project = typeof(ReleaseVersionTests).Assembly;
        var expectedCalVer = project.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        Assert.NotNull(expectedCalVer);
        Assert.Matches(@"^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,2}(\.[0-9]+)?$", expectedCalVer);
        var release = Version.Parse(expectedCalVer);
        var expectedVersion = new Version(release.Major, release.Minor, release.Build, Math.Max(0, release.Revision));

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
            Assert.Equal(expectedCalVer, info);
            Assert.Equal(expectedVersion, assembly.GetName().Version);
        }
    }
}

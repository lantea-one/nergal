using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Exercises credential and role proof against the opt-in synthetic OpenLDAP directory.</summary>
[SupportedOSPlatform("linux")]
public sealed class LdapDirectoryIntegrationTests
{
    private const string OptIn = "Run tests/integration/ldap/check-openldap.sh to use the disposable LDAPS directory.";
    private const string Suffix = "dc=example,dc=test";
    private const string Peer = "directory.example.test";
    private const string UserPassword = "fixture-user-password";
    private const string SearchPassword = "fixture-reader-password";
    private static readonly Guid DirectoryId = new("88f172f8-c919-43d0-892f-647fdf87f8dc");

    /// <summary>Requires the explicit fixture invocation before any tests can open sockets.</summary>
    public static bool FixtureEnabled => Environment.GetEnvironmentVariable("NERGAL_LDAP_FIXTURE_PORT") is not null;

    /// <summary>A verified directory bind grants only the asserted role and the entry's own profile.</summary>
    [Theory(Skip = OptIn, SkipUnless = nameof(FixtureEnabled))]
    [InlineData("administrator", NergalRoles.Administrator, "26fccabb-d580-4e59-b2ce-4a6aa8eb4a5b")]
    [InlineData("auditor", NergalRoles.Auditor, "a5870a72-3cff-467c-8da0-cd75470cf41a")]
    public async Task ReturnsCanonicalProofAndDescriptiveMetadata(string username, string role, string entryUuid)
    {
        var proof = await VerifyAsync(Settings(), username, UserPassword);

        Assert.NotNull(proof);
        Assert.Equal($"ldap:{DirectoryId:D}:{entryUuid}", proof.ActorId);
        Assert.Equal(role, proof.Role);
        Assert.Equal(TimeSpan.Zero, proof.VerifiedAtUtc.Offset);
        if (role == NergalRoles.Administrator)
        {
            Assert.Equal(new ProfileMetadata("Fixture Administrator", "Fixture", "Administrator", "administrator@example.test"), proof.Metadata);
            Assert.Empty(proof.Diagnostics);
        }
        else
        {
            Assert.Equal(new ProfileMetadata("Fixture Auditor", "", "Auditor", ""), proof.Metadata);
            Assert.Equal(new[] { "givenName.missing", "email.invalid" }, proof.Diagnostics);
        }
    }

    /// <summary>Lookup, bind and membership failures deny a proof even with otherwise usable directory entries.</summary>
    [Theory(Skip = OptIn, SkipUnless = nameof(FixtureEnabled))]
    [InlineData("administrator", "wrong-password")]
    [InlineData("administrator", "")]
    [InlineData("absent", UserPassword)]
    [InlineData("admin*", UserPassword)]
    [InlineData("ambiguous", UserPassword)]
    [InlineData("no-membership", UserPassword)]
    [InlineData("dual-membership", UserPassword)]
    [InlineData("owner-only", UserPassword)]
    public async Task DeniesInvalidCredentialOrUnprovenMembership(string username, string password)
    {
        Assert.Null(await VerifyAsync(Settings(), username, password));
    }

    /// <summary>The search identity must prove its own credentials before looking up a user.</summary>
    [Fact(Skip = OptIn, SkipUnless = nameof(FixtureEnabled))]
    public async Task DeniesWrongSearchPassword()
    {
        Assert.Null(await VerifyAsync(Settings(), "administrator", UserPassword, "wrong-search-password"));
    }

    /// <summary>A real referral or search reference prevents accepting an otherwise complete proof.</summary>
    [Theory(Skip = OptIn, SkipUnless = nameof(FixtureEnabled))]
    [InlineData("ou=referral," + Suffix)]
    [InlineData(Suffix)]
    public async Task DeniesReferralEvenWhenOneMatchingUserIsPresent(string userBase)
    {
        Assert.Null(await VerifyAsync(Settings() with { UserBaseDn = userBase }, "administrator", UserPassword));
    }

    /// <summary>A configured IP literal can use the peer certificate's IP subject alternative name.</summary>
    [Fact(Skip = OptIn, SkipUnless = nameof(FixtureEnabled))]
    public async Task AcceptsCertificateForConfiguredIpLiteral()
    {
        var proof = await VerifyAsync(Settings(host: "127.0.0.1"), "auditor", UserPassword);
        Assert.NotNull(proof);
        Assert.Equal(NergalRoles.Auditor, proof.Role);
    }

    /// <summary>The configured TLS name remains authoritative even when the socket dials a known address.</summary>
    [Fact(Skip = OptIn, SkipUnless = nameof(FixtureEnabled))]
    public async Task DeniesWrongPeerName()
    {
        Assert.Null(await VerifyAsync(Settings(host: "wrong-peer.example.test"), "administrator", UserPassword));
    }

    /// <summary>The script runs this case in a separate process with an unrelated CA bundle.</summary>
    [Fact(Skip = OptIn, SkipUnless = nameof(FixtureEnabled))]
    public async Task DeniesUntrustedPeer()
    {
        Assert.Null(await VerifyAsync(Settings(), "administrator", UserPassword));
    }

    /// <summary>A reserved local port without a TCP listener produces an actual refused connection.</summary>
    [Fact(Skip = OptIn, SkipUnless = nameof(FixtureEnabled))]
    public async Task DeniesUnavailableDirectory()
    {
        using var unavailable = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        unavailable.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var endpoint = Assert.IsType<IPEndPoint>(unavailable.LocalEndPoint);

        Assert.Null(await VerifyAsync(Settings(port: endpoint.Port), "administrator", UserPassword));
    }

    private static LdapDirectorySettings Settings(string host = Peer, int? port = null)
    {
        var fixturePort = port ?? int.Parse(Environment.GetEnvironmentVariable("NERGAL_LDAP_FIXTURE_PORT")!, CultureInfo.InvariantCulture);
        return new LdapDirectorySettings(DirectoryId, $"ldaps://{host}:{fixturePort}", "ou=people," + Suffix,
            "cn=reader," + Suffix, "uid", "cn=administrators,ou=roles," + Suffix, "cn=auditors,ou=roles," + Suffix,
            new LdapProfileMapping("displayName", "givenName", "sn", "mail"));
    }

    private static Task<LdapDirectoryProof?> VerifyAsync(LdapDirectorySettings settings, string username, string password,
        string searchPassword = SearchPassword) => new LdapDirectoryAuthenticator().VerifyAsync(settings, IPAddress.Loopback,
        searchPassword, username, password, TestContext.Current.CancellationToken);
}

using System.Text;
using Nergal.Core.Identity;

namespace Nergal.Core.Tests;

/// <summary>Verifies the LDAP inputs and projections without depending on a directory or network.</summary>
public sealed class LdapDirectoryContractTests
{
    private static readonly Guid DirectoryId = Guid.Parse("a83ae75e-84b4-492d-a702-f78cd682bf14");
    private static readonly Guid EntryId = Guid.Parse("e41d2c17-4138-4938-a16f-e7c1819726a0");
    private static readonly LdapDirectorySettings Settings = new(DirectoryId, "ldaps://directory.example", "ou=users,dc=example",
        "cn=reader,dc=example", "uid", "cn=admins,dc=example", "cn=auditors,dc=example", new());

    /// <summary>Accepts one TLS endpoint with either the default or an explicit port.</summary>
    [Theory]
    [InlineData("ldaps://directory.example", 636)]
    [InlineData("ldaps://directory.example:1636/", 1636)]
    [InlineData("ldaps://[::1]:1636", 1636)]
    public void Endpoint_AcceptsSingleLdapsPeer(string address, int port)
    {
        var settings = Settings with { ServerUri = address };
        Assert.True(settings.IsValid);
        Assert.Equal(port, settings.GetEndpoint().Port);
    }

    /// <summary>Refuses unsecured or ambiguous endpoints before any credential can be sent.</summary>
    [Theory]
    [InlineData("ldap://directory.example")]
    [InlineData("ldaps://reader@directory.example")]
    [InlineData("ldaps://directory.example/.")]
    [InlineData("ldaps://directory.example/dc=example")]
    [InlineData("ldaps://directory.example?")]
    [InlineData("ldaps://directory.example#")]
    [InlineData("ldaps://directory.example:0")]
    [InlineData("ldaps://directory.example:")]
    [InlineData("ldaps://directory.example directory-two.example")]
    public void Endpoint_RejectsUnsecuredOrAmbiguousInput(string address)
    {
        var settings = Settings with { ServerUri = address };
        Assert.False(settings.IsValid);
        Assert.Throws<InvalidOperationException>(() => settings.GetEndpoint());
    }

    /// <summary>Role groups and the service bind must be explicitly configured.</summary>
    [Fact]
    public void Settings_RejectsCoincidentRolesAndEmptyBind()
    {
        Assert.False((Settings with { AuditorGroupDn = Settings.AdministratorGroupDn.ToUpperInvariant() }).IsValid);
        Assert.False((Settings with { SearchBindDn = " " }).IsValid);
        Assert.False((Settings with { LoginAttribute = "userPassword" }).IsValid);
    }

    /// <summary>Names can contain literal LDAP punctuation and Unicode inside a bounded assertion value.</summary>
    [Fact]
    public void Lookup_ValidatesLiteralNameAndSelector()
    {
        Assert.True(LdapUserLookup.IsValidUsername("a*()\\é"));
        Assert.False(LdapUserLookup.IsValidAttribute("uid;binary"));
        Assert.False(LdapUserLookup.IsValidUsername("a\0"));
        Assert.False(LdapUserLookup.IsValidUsername(new string('a', 129)));
        Assert.False(LdapUserLookup.IsValidUsername(new string('\ud800', 1)));
    }

    /// <summary>Actor attribution binds the immutable directory and entry UUIDs.</summary>
    [Fact]
    public void ActorKey_SeparatesDirectoriesAndRequiresCanonicalNonemptyIds()
    {
        var actor = ControllerActorIdentity.FromLdapAccount(DirectoryId, EntryId);
        Assert.True(ControllerActorIdentity.IsValid(actor));
        Assert.NotEqual(actor, ControllerActorIdentity.FromLdapAccount(EntryId, DirectoryId));
        Assert.False(ControllerActorIdentity.IsValid("ldap:" + actor[5..].ToUpperInvariant()));
        Assert.False(ControllerActorIdentity.IsValid($"ldap:{DirectoryId:D}:{Guid.Empty:D}"));
        Assert.Throws<ArgumentException>(() => ControllerActorIdentity.FromLdapAccount(Guid.Empty, EntryId));
    }

    /// <summary>Missing, invalid and multivalued metadata remain distinct from enabled and valid defaults.</summary>
    [Fact]
    public void ProfileMapping_ProjectsBoundedSingleValuesWithValueFreeDiagnostics()
    {
        var mapping = new LdapProfileMapping("displayName", "givenName", "sn", "mail");
        var attributes = new Dictionary<string, IReadOnlyList<byte[]>>
        {
            ["DISPLAYNAME"] = [Encoding.UTF8.GetBytes("Example Person")],
            ["givenName"] = [[0xc3]],
            ["mail"] = [Encoding.UTF8.GetBytes("first@example.test"), Encoding.UTF8.GetBytes("second@example.test")],
        };

        var result = mapping.Project(attributes);
        Assert.Equal(new ProfileMetadata("Example Person"), result.Metadata);
        Assert.Equal(["givenName.invalid", "familyName.missing", "email.invalid"], result.Diagnostics);
        Assert.Equal(new ProfileMetadata("Example Person", "Local name"), new ProfileMetadata(GivenName: "Local name").Over(result.Metadata));
        Assert.Empty(new LdapProfileMapping().Project(attributes).Diagnostics);
    }

    /// <summary>Uses LDAP metadata as per-field defaults while retaining immutable directory provenance.</summary>
    [Fact]
    public void ProfileSnapshot_UsesDirectoryDefaultsWithIndependentOverrides()
    {
        var observed = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.FromHours(2));
        var diagnostics = new List<string> { "familyName.missing" };
        var defaults = new LdapProfileSnapshot(DirectoryId, 3,
            new ProfileMetadata("Directory Name", "Example", Email: "person@example.test"), observed, diagnostics);
        var profile = new UserProfileSnapshot(ControllerActorIdentity.FromLdapAccount(DirectoryId, EntryId),
            "fixture-user", NergalRoles.Auditor, null, null, "Local Name", 1, null, LdapProvider: defaults);
        diagnostics.Clear();

        Assert.Equal(DirectoryId, defaults.DirectoryId);
        Assert.Equal(3, defaults.MappingVersion);
        Assert.Equal(TimeSpan.Zero, defaults.ObservedUtc.Offset);
        Assert.Equal(observed, defaults.ObservedUtc);
        Assert.Equal(["familyName.missing"], defaults.Diagnostics);
        Assert.Equal(new ProfileMetadata("Local Name", "Example", Email: "person@example.test"), profile.Effective);
    }

    /// <summary>Literal selectors are deduplicated in requests, while duplicate returned names are ambiguous.</summary>
    [Fact]
    public void ProfileMapping_RejectsSelectorSyntaxAndAmbiguousAttributes()
    {
        Assert.False(new LdapProfileMapping("displayName;lang-en").IsValid);
        var mapping = new LdapProfileMapping("cn", "CN");
        Assert.False(new LdapProfileMapping("userPassword").IsValid);
        Assert.Equal(["cn"], mapping.SelectedAttributes);
        IReadOnlyList<byte[]> values = [Encoding.UTF8.GetBytes("Example")];
        Assert.Throws<ArgumentException>(() => mapping.Project(new Dictionary<string, IReadOnlyList<byte[]>> { ["cn"] = values, ["CN"] = values }));
    }
}

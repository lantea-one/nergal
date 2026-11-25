using System.Text;
using Nergal.Core.Identity;
using Nergal.Identity;

namespace Nergal.Web.Tests;

/// <summary>Verifies the immutable identity and stable role evidence required to accept an LDAP proof.</summary>
public sealed class LdapDirectoryProofTests
{
    private static readonly LdapGroupVersion Admin = new(Guid.Parse("165452fe-85ab-4f4f-9c8d-5538ada36331"),
        "cn=administrators,dc=example,dc=test", "administrator-original");
    private static readonly LdapGroupVersion Auditor = new(Guid.Parse("f6bdfa90-0ba4-43c2-8b2b-c444332b25ef"),
        "cn=auditors,dc=example,dc=test", "auditor-original");

    /// <summary>A mixed view across group edits may never grant a role even if the comparisons disagree.</summary>
    [Fact]
    public void ResolveRole_DeniesMixedMembershipEvidenceAndReplacedGroups()
    {
        // The administrator comparison saw membership before the change.
        // The auditor comparison saw no membership after its own group changed.
        Assert.Null(LdapDirectoryAuthenticator.ResolveRole(true, false, Admin, Auditor,
            Admin with { ChangeSequence = "administrator-modified" }, Auditor with { ChangeSequence = "auditor-modified" }));
        Assert.Null(LdapDirectoryAuthenticator.ResolveRole(true, false, Admin, Auditor,
            Admin, Auditor with { Id = Guid.Parse("93f9caed-06e8-4789-bb6f-6c8cb1120ad4") }));
        Assert.Null(LdapDirectoryAuthenticator.ResolveRole(true, false, Admin, Auditor, Admin, null));
    }

    /// <summary>Only one affirmative comparison in a stable pair can supply a role.</summary>
    [Fact]
    public void ResolveRole_RequiresExactlyOneStableGroupMatch()
    {
        Assert.Equal(NergalRoles.Administrator, LdapDirectoryAuthenticator.ResolveRole(true, false, Admin, Auditor, Admin, Auditor));
        Assert.Equal(NergalRoles.Auditor, LdapDirectoryAuthenticator.ResolveRole(false, true, Admin, Auditor, Admin, Auditor));
        Assert.Null(LdapDirectoryAuthenticator.ResolveRole(false, false, Admin, Auditor, Admin, Auditor));
        Assert.Null(LdapDirectoryAuthenticator.ResolveRole(true, true, Admin, Auditor, Admin, Auditor));
        Assert.Null(LdapDirectoryAuthenticator.ResolveRole(true, false, Admin, Admin, Admin, Admin));
    }

    /// <summary>Accepts canonical hexadecimal text in either case and rejects alternate GUID spellings.</summary>
    [Fact]
    public void EntryUuid_RequiresCanonicalHexAndHyphens()
    {
        var expected = Guid.Parse("a83ae75e-84b4-492d-a702-f78cd682bf14");
        Assert.Equal(expected, LdapDirectoryAuthenticator.ReadUuid(EntryWithUuid(expected.ToString("D").ToUpperInvariant())));
        Assert.Null(LdapDirectoryAuthenticator.ReadUuid(EntryWithUuid("+83ae75e-84b4-492d-a702-f78cd682bf14")));
        Assert.Null(LdapDirectoryAuthenticator.ReadUuid(EntryWithUuid(Guid.Empty.ToString("D"))));
    }

    private static LdapWireEntry EntryWithUuid(string value) => new("uid=example,dc=example,dc=test",
        new Dictionary<string, IReadOnlyList<byte[]>> { ["entryUUID"] = [Encoding.ASCII.GetBytes(value)] });
}

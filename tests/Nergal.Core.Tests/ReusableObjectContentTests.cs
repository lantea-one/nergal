using Nergal.Core.Controller;

namespace Nergal.Core.Tests;

/// <summary>Typed lists cannot acquire ambiguous addresses, mixed families or caller mutations.</summary>
public sealed class ReusableObjectContentTests
{
    /// <summary>Canonical host prefixes and ordering remain isolated from caller-owned collections.</summary>
    [Fact]
    public void Content_SnapshotsAndCanonicalizesWithoutMerging()
    {
        var entries = new[] { "192.0.2.10", "192.0.2.0/24" };
        var content = new ReusableObjectContent("clients", ReusableObjectKind.Ipv4, "Synthetic", entries);
        entries[0] = "203.0.113.1";
        Assert.Equal(new[] { "192.0.2.0/24", "192.0.2.10/32" }, content.Entries);
        Assert.Throws<NotSupportedException>(() => ((IList<string>)content.Entries)[0] = "changed");
        Assert.Equal("2001:db8::1/128", new ReusableObjectContent("clients6", ReusableObjectKind.Ipv6, "", ["2001:DB8::1"]).Entries.Single());
        Assert.Equal("443", new ReusableObjectContent("web", ReusableObjectKind.Port, "", ["00443"]).Entries.Single());
    }

    /// <summary>Unsupported or ambiguous entries fail explicitly rather than weakening a later policy reference.</summary>
    [Theory]
    [InlineData(ReusableObjectKind.Ipv4, "example.invalid", "object.addressInvalid")]
    [InlineData(ReusableObjectKind.Ipv4, "127.1", "object.addressInvalid")]
    [InlineData(ReusableObjectKind.Ipv4, "192.0.2.1/24", "object.prefixInvalid")]
    [InlineData(ReusableObjectKind.Ipv4, "2001:db8::1", "object.familyMismatch")]
    [InlineData(ReusableObjectKind.Ipv6, "192.0.2.1", "object.familyMismatch")]
    [InlineData(ReusableObjectKind.Ipv6, "fe80::1%eth0", "object.addressInvalid")]
    [InlineData(ReusableObjectKind.Ipv6, "::ffff:192.0.2.1", "object.addressInvalid")]
    [InlineData(ReusableObjectKind.Port, "0", "object.portInvalid")]
    [InlineData(ReusableObjectKind.Port, "65536", "object.portInvalid")]
    [InlineData(ReusableObjectKind.Port, "80-443", "object.portInvalid")]
    [InlineData(ReusableObjectKind.Port, "https", "object.portInvalid")]
    [InlineData(ReusableObjectKind.Ipv4, " 192.0.2.1", "object.entryInvalid")]
    public void Content_RejectsInvalidEntry(ReusableObjectKind kind, string entry, string diagnostic)
    {
        Assert.StartsWith(diagnostic, Assert.Throws<ArgumentException>(() => new ReusableObjectContent("synthetic", kind, "", [entry])).Message);
    }

    /// <summary>Limits and normalized duplicates cannot be bypassed through alternate spelling or unknown types.</summary>
    [Fact]
    public void Content_RejectsInvalidIdentityBoundsAndDuplicates()
    {
        Assert.Throws<ArgumentException>(() => new ReusableObjectContent("Bad name", ReusableObjectKind.Port, "", ["443"]));
        Assert.Throws<ArgumentException>(() => new ReusableObjectContent("valid", (ReusableObjectKind)99, "", ["443"]));
        Assert.Throws<ArgumentException>(() => new ReusableObjectContent("valid", ReusableObjectKind.Port, new string('a', 501), ["443"]));
        Assert.Throws<ArgumentException>(() => new ReusableObjectContent("valid", ReusableObjectKind.Port, "", []));
        Assert.Throws<ArgumentException>(() => new ReusableObjectContent("valid", ReusableObjectKind.Port, "", Enumerable.Range(1, 65).Select(i => i.ToString(System.Globalization.CultureInfo.InvariantCulture))));
        Assert.StartsWith("object.duplicateEntry", Assert.Throws<ArgumentException>(() => new ReusableObjectContent("valid", ReusableObjectKind.Ipv4, "", ["192.0.2.1", "192.0.2.1/32"])).Message);
        Assert.StartsWith("object.duplicateEntry", Assert.Throws<ArgumentException>(() => new ReusableObjectContent("valid", ReusableObjectKind.Port, "", ["443", "00443"])).Message);
    }
}

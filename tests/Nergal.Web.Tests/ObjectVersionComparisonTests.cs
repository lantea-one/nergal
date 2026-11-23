using Nergal.Core.Controller;

namespace Nergal.Web.Tests;

/// <summary>Entry comparisons are directional read-only facts, never an approximation of network coverage or enforcement.</summary>
public sealed class ObjectVersionComparisonTests
{
    private static readonly Guid Id = Guid.Parse("34a64371-b1e5-4b9b-ad9b-ed0ac0a814a1");
    private static ReusableObjectVersion Version(int version, ReusableObjectContent content, Guid? id = null) =>
        new(id ?? Id, version, content, content.Digest, "synthetic", DateTimeOffset.Parse("2026-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));

    /// <summary>A replacement reports both sides, retains exact unchanged CIDRs and leaves snapshots intact in either direction.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Compare_ReportsExactEntriesInRequestedDirection(bool reverse)
    {
        var old = Version(1, new("clients", ReusableObjectKind.Ipv4, "Old", ["192.0.2.0/24", "198.51.100.10"]));
        var current = Version(2, new("clients", ReusableObjectKind.Ipv4, "New", ["192.0.2.0/24", "203.0.113.10"]));
        var comparison = ObjectVersionComparison.Create(reverse ? current : old, reverse ? old : current);
        Assert.Equal(new[] { reverse ? "198.51.100.10/32" : "203.0.113.10/32" }, comparison.AddedEntries);
        Assert.Equal(new[] { reverse ? "203.0.113.10/32" : "198.51.100.10/32" }, comparison.RemovedEntries);
        Assert.Equal(1, comparison.UnchangedEntryCount);
        Assert.True(comparison.DescriptionChanged);
        Assert.Same(reverse ? current : old, comparison.Baseline);
        Assert.Equal(new[] { "192.0.2.0/24", "198.51.100.10/32" }, old.Content.Entries);
        Assert.Throws<NotSupportedException>(() => ((IList<string>)comparison.AddedEntries).Add("invalid"));
    }

    /// <summary>Equal entry sets can still have a meaningful description change; same-version comparison is empty.</summary>
    [Fact]
    public void Compare_DistinguishesMetadataFromEntries()
    {
        var first = Version(1, new("ports", ReusableObjectKind.Port, "Old", ["443", "80"]));
        var next = Version(2, new("ports", ReusableObjectKind.Port, "New", ["080", "443"]));
        var comparison = ObjectVersionComparison.Create(first, next);
        Assert.Empty(comparison.AddedEntries); Assert.Empty(comparison.RemovedEntries);
        Assert.Equal(2, comparison.UnchangedEntryCount); Assert.True(comparison.DescriptionChanged);
        Assert.False(ObjectVersionComparison.Create(first, first).DescriptionChanged);
    }

    /// <summary>Overlapping prefixes are entry changes, not a computed expansion or contraction of access.</summary>
    [Fact]
    public void Compare_DoesNotApproximatePrefixCoverage()
    {
        var first = Version(1, new("clients", ReusableObjectKind.Ipv6, "", ["2001:db8::/64"]));
        var next = Version(2, new("clients", ReusableObjectKind.Ipv6, "", ["2001:db8::/48"]));
        var comparison = ObjectVersionComparison.Create(first, next);
        Assert.Equal(new[] { "2001:db8::/48" }, comparison.AddedEntries);
        Assert.Equal(new[] { "2001:db8::/64" }, comparison.RemovedEntries);
        Assert.Equal(0, comparison.UnchangedEntryCount);
    }

    /// <summary>Unrelated identities or types cannot be presented as a version change in one list.</summary>
    [Fact]
    public void Compare_RejectsUnrelatedSnapshotsAndMissingInput()
    {
        var first = Version(1, new("ports", ReusableObjectKind.Port, "", ["443"]));
        foreach (var other in new[]
        {
            Version(2, first.Content, Guid.NewGuid()),
            Version(2, new("other", ReusableObjectKind.Port, "", ["443"])),
            Version(2, new("ports", ReusableObjectKind.Ipv4, "", ["192.0.2.1"]))
        }) { Assert.Equal("object.comparisonIdentityMismatch", Assert.Throws<ArgumentException>(() => ObjectVersionComparison.Create(first, other)).Message); }
        Assert.Throws<ArgumentNullException>(() => ObjectVersionComparison.Create(null!, first));
        Assert.Throws<ArgumentNullException>(() => ObjectVersionComparison.Create(first, null!));
    }
}

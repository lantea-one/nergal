using System.Runtime.Versioning;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Core.Policy;

namespace Nergal.Web.Tests;

/// <summary>Draft changes retain complete address pins, while database history remains the authority for every snapshot.</summary>
[SupportedOSPlatform("linux")]
public sealed class PostroutingAddressAuthoringTests
{
    private static FirewallPolicyBundle Bundle() => new(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, []),
        new(1, [], [new(IpFamily.IPv4, new("192.0.2.0/24"), "198.51.100.1", Destination: new("203.0.113.0/24"),
            InputInterface: "lan0", OutputInterface: "wan0", Protocol: FilterProtocol.Tcp, DestinationPort: 443,
            NegateSource: true, NegateDestination: true, Enabled: false)]));
    private static VisualPostroutingInput Input(string? source = null, string? destination = null) => new("ipv4", "snat", source, destination,
        "198.51.100.1", "lan0", "wan0", "tcp", "443", true, true, false, false, "Retained pins");
    private static SnatRule Rule(string json) => PolicyBundleJsonCodec.DecodeBundle(json).Value!.Nat!.SnatRules[0]!;

    /// <summary>Guided and legacy edits retain pins; conflicting literals fail, and clearing required SNAT source restrictions is denied.</summary>
    [Fact]
    public void Draft_PreservesPinsAndRejectsImplicitRestrictionRemoval()
    {
        var content = new ReusableObjectContent("networks", ReusableObjectKind.Ipv4, "", ["192.0.2.0/24", "203.0.113.0/24"]);
        var reference = new PolicyObjectReference(Guid.Parse("11111111-1111-4111-8111-111111111111"), 1, content);
        var json = PolicyBundleJsonCodec.EncodeBundle(Bundle());
        foreach (var slot in new[] { "source", "destination" })
        { Assert.True(PolicyObjectAuthoring.TrySet(json, 0, slot, reference, out var attached, out _, "postrouting")); json = attached!; }
        var pinned = Rule(json);
        Assert.False(pinned.Enabled); Assert.True(pinned.NegateSource); Assert.True(pinned.NegateDestination);
        Assert.True(PolicyAuthoringService.TrySetPostrouting(json, 0, Input(), out var edited, out _));
        Assert.Equal(reference, Rule(edited!).SourceObject); Assert.Equal(reference, Rule(edited!).DestinationObject);
        Assert.False(PolicyAuthoringService.TrySetPostrouting(json, 0, Input("192.0.2.0/24"), out _, out _));
        Assert.False(PolicyAuthoringService.TrySetPostrouting(json, 0, Input(destination: "203.0.113.0/24"), out _, out _));
        Assert.True(PolicyAuthoringService.TryUpdateSnatRule(json, 0, new("ipv4", null, "198.51.100.1", null, "wan0", "Legacy edit"), out var legacy, out _));
        Assert.Equal(reference, Rule(legacy!).SourceObject); Assert.Equal(reference, Rule(legacy!).DestinationObject);
        Assert.False(PolicyObjectAuthoring.TrySet(json, 0, "source", null, out _, out _, "postrouting"));
        Assert.True(PolicyObjectAuthoring.TrySet(json, 0, "destination", null, out var removed, out _, "postrouting"));
        Assert.Null(Rule(removed!).DestinationObject); Assert.False(Rule(removed!).NegateDestination);
        Assert.Equal(reference, Rule(removed!).SourceObject); Assert.Equal(443, Rule(removed!).DestinationPort);
    }

    /// <summary>Literal source/destination sets are authored without JSON and keep dormant state; invalid overlap/family changes fail.</summary>
    [Fact]
    public void GuidedForms_AuthorCompleteLiteralSetsAndDenyInvalidNetworks()
    {
        var json = PolicyBundleJsonCodec.EncodeBundle(Bundle());
        var input = Input("192.0.2.0/24, 198.51.100.0/24", "203.0.113.10/32, 203.0.113.20/32");
        Assert.True(PolicyAuthoringService.TrySetPostrouting(json, 0, input, out var changed, out _));
        Assert.Equal(2, Rule(changed!).SourcePrefixes!.Count); Assert.Equal(2, Rule(changed!).DestinationPrefixes!.Count);
        Assert.False(Rule(changed!).Enabled);
        Assert.False(PolicyAuthoringService.TrySetPostrouting(json, 0, input with { Source = "192.0.2.0/24,192.0.2.10/32" }, out _, out _));
        Assert.False(PolicyAuthoringService.TrySetPostrouting(json, 0, input with { Destination = "2001:db8::/64,2001:db8:2::/64" }, out _, out _));
    }

    /// <summary>Every postrouting address snapshot is verified against immutable SQL history; later edits cannot alter saved restrictions.</summary>
    [Fact]
    public void Database_RecordsAddressUsageAndRejectsForgedVersions()
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var path = Path.Combine(Path.GetTempPath(), "ng-nat-address-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var store = ControllerStateStore.Initialize(new(path));
            var actor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-4111-8111-111111111111"));
            var item = store.SaveReusableObject(null, 0, new("networks", ReusableObjectKind.Ipv4, "", ["192.0.2.0/24", "203.0.113.0/24"]), actor, NergalRoles.Administrator);
            var reference = new PolicyObjectReference(item.Id, item.Version, item.Content);
            var json = PolicyBundleJsonCodec.EncodeBundle(Bundle());
            foreach (var slot in new[] { "source", "destination" })
            { Assert.True(PolicyObjectAuthoring.TrySet(json, 0, slot, reference, out var next, out _, "postrouting")); json = next!; }
            var report = PolicyAuthoringService.EvaluateDraft(json, store); Assert.True(report.IsValid);
            var saved = store.SavePolicyRevision(json, report.CandidateDigest!, actor, NergalRoles.Administrator);
            Assert.Equal(new[] { "nat.snatRules[0].destinationObject", "nat.snatRules[0].sourceObject" }, store.ListPolicyObjectUsage(item.Id).Select(u => u.Path).Order(StringComparer.Ordinal));
            store.SaveReusableObject(item.Id, 1, new("networks", ReusableObjectKind.Ipv4, "Later", ["198.51.100.10"]), actor, NergalRoles.Administrator);
            Assert.Equal(json, store.GetPolicyRevision(saved.Revision)!.PolicyJson);
            foreach (var slot in new[] { "sourceObject", "destinationObject" })
            {
                var forged = System.Text.Json.Nodes.JsonNode.Parse(json)!;
                forged["nat"]!["snatRules"]![0]![slot]!["version"] = 2;
                Assert.False(PolicyAuthoringService.EvaluateDraft(forged.ToJsonString(), store).IsValid);
            }
            Assert.Single(store.ListPolicyRevisions());
        }
        finally { Directory.Delete(path, true); }
    }
}

using System.Runtime.Versioning;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Core.Policy;

namespace Nergal.Web.Tests;

/// <summary>Bridge list edits retain MAC/IP pinning, graph, state and exact immutable database versions.</summary>
[SupportedOSPlatform("linux")]
public sealed class BridgeAddressAuthoringTests
{
    private static FirewallPolicyBundle Bundle()
    {
        var rule = new BridgeFilterRule(BridgeEtherType.IPv4, FilterVerdict.Drop, BridgeName: "br0", SourceMac: new("02:00:00:00:00:01"),
            DestinationMac: new("02:00:00:00:00:02"), Family: IpFamily.IPv4, Source: new("192.0.2.0/24"), Destination: new("203.0.113.0/24"),
            Protocol: FilterProtocol.Tcp, DestinationPorts: [443, 9001], Enabled: false);
        return new(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, []), bridge: new(1, FilterVerdict.Drop,
            [rule with { JumpTarget = "service" }], -5, [new("service", [rule with { Return = true }])]));
    }
    private static BridgeFilterRule Rule(string json, string scope) { var b = PolicyBundleJsonCodec.DecodeBundle(json).Value!.Bridge!; return (scope == "bridge" ? b.Rules[0] : b.SubChains[0].Rules[0])!; }
    private static VisualExtendedBridgeInput Input(string scope) => new("ipv4", scope == "bridge" ? "jump" : "return", null, null,
        "br0", "02:00:00:00:00:01", "02:00:00:00:00:02", false, false, "ipv4", null, null, "tcp", "443,9001", scope == "bridge" ? "service" : null, "Retained pins");

    /// <summary>Guided edits/reordering keep every pin and MAC constraint; removal is explicit and wrong-family/literal conflicts fail.</summary>
    [Theory]
    [InlineData("bridge")]
    [InlineData("bridgeChain")]
    public void Draft_PreservesCompleteBridgeIntent(string scope)
    {
        var reference = new PolicyObjectReference(Guid.Parse("11111111-1111-4111-8111-111111111111"), 1,
            new("networks", ReusableObjectKind.Ipv4, "", ["192.0.2.0/24", "203.0.113.0/24"]));
        var json = PolicyBundleJsonCodec.EncodeBundle(Bundle()); var chain = scope == "bridge" ? null : "service";
        foreach (var slot in new[] { "source", "destination" })
        { Assert.True(PolicyObjectAuthoring.TrySet(json, 0, slot, reference, out var attached, out _, scope, chain)); json = attached!; }
        var original = Rule(json, scope);
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(json, "edit", chain, 0, Input(scope), out var edited, out _));
        var after = Rule(edited!, scope);
        Assert.Equal(reference, after.SourceObject); Assert.Equal(reference, after.DestinationObject);
        Assert.Equal(original.SourceMac, after.SourceMac); Assert.Equal(original.DestinationMac, after.DestinationMac);
        Assert.Equal(original.JumpTarget, after.JumpTarget); Assert.Equal(original.Return, after.Return); Assert.False(after.Enabled);
        Assert.Equal(original.DestinationPorts, after.DestinationPorts);
        Assert.False(PolicyAuthoringService.TrySetExtendedBridgeRule(json, "edit", chain, 0, Input(scope) with { Family = "none" }, out _, out _));
        Assert.False(PolicyAuthoringService.TrySetExtendedBridgeRule(json, "edit", chain, 0, Input(scope) with { Source = "192.0.2.0/24" }, out _, out _));
        foreach (var slot in new[] { "source", "destination" })
        {
            Assert.True(PolicyObjectAuthoring.TrySet(json, 0, slot, null, out var removed, out _, scope, chain));
            Assert.Equal(original.SourceMac, Rule(removed!, scope).SourceMac);
            Assert.Null(slot == "source" ? Rule(removed!, scope).SourceObject : Rule(removed!, scope).DestinationObject);
            Assert.Equal(IpFamily.IPv4, Rule(removed!, scope).Family); Assert.False(Rule(removed!, scope).Enabled);
        }
    }

    /// <summary>Both chains author literal sets without JSON, retaining graph/state and rejecting invalid overlap.</summary>
    [Theory]
    [InlineData("bridge")]
    [InlineData("bridgeChain")]
    public void GuidedForms_AuthorBoundedLiteralSets(string scope)
    {
        var input = Input(scope) with { Source = "192.0.2.0/24,198.51.100.0/24", Destination = "203.0.113.10/32,203.0.113.20/32" };
        var json = PolicyBundleJsonCodec.EncodeBundle(Bundle()); var chain = scope == "bridge" ? null : "service";
        Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(json, "edit", chain, 0, input, out var changed, out _));
        Assert.Equal(2, Rule(changed!, scope).SourcePrefixes!.Count); Assert.Equal(2, Rule(changed!, scope).DestinationPrefixes!.Count);
        Assert.False(Rule(changed!, scope).Enabled);
        Assert.False(PolicyAuthoringService.TrySetExtendedBridgeRule(json, "edit", chain, 0, input with { Source = "192.0.2.0/24,192.0.2.10/32" }, out _, out _));
    }

    /// <summary>All four bridge matcher paths bind immutable SQL history; forged versions cannot create a revision.</summary>
    [Fact]
    public void Database_ValidatesEveryBridgeAddressReferenceAndUsage()
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var path = Path.Combine(Path.GetTempPath(), "ng-bridge-address-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var store = ControllerStateStore.Initialize(new(path)); var actor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-4111-8111-111111111111"));
            var item = store.SaveReusableObject(null, 0, new("networks", ReusableObjectKind.Ipv4, "", ["192.0.2.0/24", "203.0.113.0/24"]), actor, NergalRoles.Administrator);
            var json = PolicyBundleJsonCodec.EncodeBundle(Bundle());
            foreach (var scope in new[] { "bridge", "bridgeChain" })
            {
                foreach (var slot in new[] { "source", "destination" })
                { Assert.True(PolicyObjectAuthoring.TrySet(json, 0, slot, new(item.Id, item.Version, item.Content), out var next, out _, scope, scope == "bridge" ? null : "service")); json = next!; }
            }
            var report = PolicyAuthoringService.EvaluateDraft(json, store); Assert.True(report.IsValid);
            var revision = store.SavePolicyRevision(json, report.CandidateDigest!, actor, NergalRoles.Administrator);
            Assert.Equal(4, store.ListPolicyObjectUsage(item.Id).Count);
            store.SaveReusableObject(item.Id, 1, new("networks", ReusableObjectKind.Ipv4, "Later", ["198.51.100.10"]), actor, NergalRoles.Administrator);
            Assert.Equal(json, store.GetPolicyRevision(revision.Revision)!.PolicyJson);
            foreach (var scope in new[] { "bridge", "bridgeChain" })
            {
                foreach (var slot in new[] { "sourceObject", "destinationObject" })
                {
                    var forged = System.Text.Json.Nodes.JsonNode.Parse(json)!;
                    var rule = scope == "bridge" ? forged["bridge"]!["rules"]![0]! : forged["bridge"]!["subChains"]![0]!["rules"]![0]!;
                    rule[slot]!["version"] = 2;
                    Assert.False(PolicyAuthoringService.EvaluateDraft(forged.ToJsonString(), store).IsValid);
                }
            }
            Assert.Single(store.ListPolicyRevisions());
        }
        finally { Directory.Delete(path, true); }
    }
}

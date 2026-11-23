using System.Runtime.Versioning;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Core.Policy;

namespace Nergal.Web.Tests;

/// <summary>New matcher scopes preserve independent intent and remain bound to immutable authoritative object history.</summary>
[SupportedOSPlatform("linux")]
public sealed class TransportPolicyObjectTests
{
    private static readonly string Actor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-4111-8111-111111111111"));
    private static FirewallPolicyBundle Bundle() => new(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, [], forwardTcpMssClamp: 1360, forwardTcpMssClampEnabled: false),
        new(1, [], [new(IpFamily.IPv4, new("192.0.2.0/24"), null, Action: NatPostroutingAction.Masquerade, Protocol: FilterProtocol.Tcp, DestinationPort: 443, Enabled: false)]),
        new(1, FilterVerdict.Drop, [new(BridgeEtherType.Any, FilterVerdict.Drop, BridgeName: "br0", SourceMac: new("02:00:00:00:00:01"), Protocol: FilterProtocol.Tcp, DestinationPort: 443, JumpTarget: "service", Enabled: false)], -5,
            [new("service", [new(BridgeEtherType.Any, FilterVerdict.Drop, Protocol: FilterProtocol.Tcp, DestinationPort: 443, Return: true, Enabled: false)])]));
    private static string? Chain(string scope) => scope == "bridgeChain" ? "service" : null;
    private static PolicyObjectReference Reference() => new(Guid.NewGuid(), 1, new("services", ReusableObjectKind.Port, "", ["80", "443"]));

    /// <summary>Attachment, ordinary editing and explicit removal retain disabled state, other restrictions and every unrelated policy section.</summary>
    [Theory]
    [InlineData("postrouting")]
    [InlineData("bridge")]
    [InlineData("bridgeChain")]
    public void Authoring_AllTransportScopesPreservePinnedIntent(string scope)
    {
        var original = PolicyBundleJsonCodec.EncodeBundle(Bundle(), indented: true);
        var reference = Reference();
        Assert.True(PolicyObjectAuthoring.TrySet(original, 0, "ports", reference, out var attached, out _, scope, Chain(scope)));
        var bundle = PolicyBundleJsonCodec.DecodeBundle(attached!).Value!;
        Assert.Equal(reference, Assert.Single(PolicyObjectReferences.Enumerate(bundle)).Reference);
        string? edited;
        if (scope == "postrouting")
        {
            Assert.True(PolicyAuthoringService.TrySetPostrouting(attached!, 0, new("ipv4", "masquerade", "192.0.2.0/24", null, null, null, null, "tcp", null, false, false, false, false, null), out edited, out _));
            Assert.False(PolicyAuthoringService.TrySetPostrouting(attached!, 0, new("ipv4", "masquerade", "192.0.2.0/24", null, null, null, null, "any", null, false, false, false, false, null), out _, out _));
            Assert.False(PolicyAuthoringService.TrySetPostrouting(attached!, 0, new("ipv4", "masquerade", "192.0.2.0/24", null, null, null, null, "tcp", "22", false, false, false, false, null), out _, out _));
        }
        else
        {
            Assert.True(PolicyAuthoringService.TrySetExtendedBridgeRule(attached!, "edit", Chain(scope), 0,
                new("any", scope == "bridge" ? "jump" : "return", null, null, scope == "bridge" ? "br0" : null,
                    scope == "bridge" ? "02:00:00:00:00:01" : null, null, false, false, "none", null, null, "tcp", null,
                    scope == "bridge" ? "service" : null, null), out edited, out _));
        }
        Assert.Equal(attached, edited);
        Assert.All(PolicyRuleStates.Enumerate(PolicyBundleJsonCodec.DecodeBundle(edited!).Value!), s => Assert.False(s.Enabled));
        Assert.True(PolicyObjectAuthoring.TrySet(edited!, 0, "ports", null, out var removed, out _, scope, Chain(scope)));
        var cleared = PolicyBundleJsonCodec.DecodeBundle(removed!).Value!;
        Assert.Empty(PolicyObjectReferences.Enumerate(cleared)); Assert.False(cleared.Filter.ForwardTcpMssClampEnabled);
        Assert.Equal("service", cleared.Bridge!.Rules[0]!.JumpTarget); Assert.True(cleared.Bridge.SubChains[0].Rules[0]!.Return);
        Assert.Equal("02:00:00:00:00:01", cleared.Bridge.Rules[0]!.SourceMac!.Value);
        Assert.False(PolicyObjectAuthoring.TrySet(removed!, 0, "ports", null, out _, out _, scope, Chain(scope)));
        Assert.False(PolicyObjectAuthoring.TrySet(original, 0, "source", reference, out _, out _, scope, Chain(scope)));
        Assert.False(PolicyObjectAuthoring.TrySet(original, 0, "ports", reference, out _, out _, scope, scope == "bridgeChain" ? "missing" : "unexpected"));
    }

    /// <summary>Saved usage covers all scopes; later library edits cannot change old intent and forged snapshots fail transactionally.</summary>
    [Fact]
    public void Persistence_ValidatesEveryTransportScopeAndRetainsOldVersions()
    {
        var path = Path.Combine(Path.GetTempPath(), "ng-transport-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var store = ControllerStateStore.Initialize(new(path));
            var item = store.SaveReusableObject(null, 0, new("services", ReusableObjectKind.Port, "", ["80", "443"]), Actor, NergalRoles.Administrator);
            var json = PolicyBundleJsonCodec.EncodeBundle(Bundle());
            foreach (var scope in new[] { "postrouting", "bridge", "bridgeChain" })
            {
                var wrong = new PolicyObjectReference(item.Id, 1, new("services", ReusableObjectKind.Port, "", ["22"]));
                Assert.True(PolicyObjectAuthoring.TrySet(json, 0, "ports", wrong, out var forged, out _, scope, Chain(scope)));
                Assert.False(PolicyAuthoringService.EvaluateDraft(forged!, store).IsValid);
                Assert.Throws<ControllerStateException>(() => store.SavePolicyRevision(forged!, new string('a', 64), Actor, NergalRoles.Administrator));
                Assert.Empty(store.ListPolicyRevisions()); Assert.Single(store.ListAuditEntries());
            }
            foreach (var scope in new[] { "postrouting", "bridge", "bridgeChain" })
            {
                Assert.True(PolicyObjectAuthoring.TrySet(json, 0, "ports", new(item.Id, item.Version, item.Content), out var next, out _, scope, Chain(scope)));
                json = next!;
            }
            var report = PolicyAuthoringService.EvaluateDraft(json, store);
            Assert.True(report.IsValid);
            var saved = store.SavePolicyRevision(json, report.CandidateDigest!, Actor, NergalRoles.Administrator);
            Assert.Equal(3, store.ListPolicyObjectUsage(item.Id).Count);
            store.SaveReusableObject(item.Id, 1, new("services", ReusableObjectKind.Port, "Later", ["8443"]), Actor, NergalRoles.Administrator);
            Assert.Equal(json, store.GetPolicyRevision(saved.Revision)!.PolicyJson);
            Assert.All(PolicyObjectReferences.Enumerate(PolicyBundleJsonCodec.DecodeBundle(json).Value!), b => Assert.Equal(1, b.Reference.Version));
        }
        finally { Directory.Delete(path, true); }
    }
}

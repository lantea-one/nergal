using System.Runtime.Versioning;
using Nergal.ControllerState;
using Nergal.Core.Identity;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web.Tests;

/// <summary>Visual editing preserves dormant rules and intent review exposes changes absent from native output.</summary>
[SupportedOSPlatform("linux")]
public sealed class RuleStateAuthoringTests
{
    private static FirewallPolicyBundle Bundle() => new(1,
        new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, Enabled: false)], forwardTcpMssClamp: 1360, forwardTcpMssClampEnabled: false),
        new(1, [new(IpFamily.IPv4, FilterProtocol.Tcp, new("192.0.2.1/32"), "198.51.100.1", Enabled: false)],
            [new(IpFamily.IPv4, new("192.0.2.0/24"), "203.0.113.1", Enabled: false)]),
        new(1, FilterVerdict.Drop, [new(BridgeEtherType.IPv4, FilterVerdict.Accept, Enabled: false)]));

    /// <summary>Every existing visual edit path preserves disabled state and MSS settings.</summary>
    [Fact]
    public void Edit_AllVisualRuleTypesPreserveEnabledState()
    {
        var json = PolicyBundleJsonCodec.EncodeBundle(Bundle());
        Assert.True(PolicyAuthoringService.TryUpdateFilterRule(json, 0, new("input", "ipv4", "tcp", "accept", "", "", "443", "", "", "", "", Description: "Changed"), out var filter, out _));
        Assert.True(PolicyAuthoringService.TryUpdateDnatRule(filter!, 0, new("ipv4", "tcp", "192.0.2.1/32", "198.51.100.2", null, null, null, null), out var dnat, out _));
        Assert.True(PolicyAuthoringService.TryUpdateSnatRule(dnat!, 0, new("ipv4", "192.0.2.0/24", "203.0.113.2", null, null), out var snat, out _));
        Assert.True(PolicyAuthoringService.TryUpdateBridgeRule(snat!, 0, new("ipv4", "accept", "lan0", null), out var bridge, out _));
        var decoded = PolicyBundleJsonCodec.DecodeBundle(bridge!).Value!;
        Assert.All(PolicyRuleStates.Enumerate(decoded), state => Assert.False(state.Enabled));
        Assert.Equal(1360, decoded.Filter.ForwardTcpMssClamp);
        Assert.Equal("Changed", decoded.Filter.Rules[0]!.Description);
        Assert.DoesNotContain("add rule", NftPolicyBundleCompiler.Compile(decoded).Candidate);
    }

    /// <summary>Changing dormant metadata remains reviewable and cannot alter a prior saved revision.</summary>
    [Fact]
    public void Review_DisabledIntentChangesRemainVisibleWithIdenticalNativeCandidate()
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var path = Path.Combine(Path.GetTempPath(), "ng-state-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var store = ControllerStateStore.Initialize(new(path));
            var actor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-4111-8111-111111111111"));
            var baseline = PolicyBundleJsonCodec.EncodeBundle(Bundle());
            var compiled = PolicyAuthoringService.EvaluateDraft(baseline, store);
            var revision = store.SavePolicyRevision(baseline, compiled.CandidateDigest!, actor, NergalRoles.Administrator);
            Assert.True(PolicyAuthoringService.TryUpdateFilterRule(baseline, 0, new("input", "ipv4", "tcp", "accept", "", "", "443", "", "", "", "", Description: "Dormant HTTPS"), out var updated, out _));
            var report = PolicyAuthoringService.EvaluateDraft(updated!, store, revision.Revision);
            Assert.True(report.IsValid); Assert.Equal(compiled.CandidateDigest, report.CandidateDigest);
            Assert.Contains("Dormant HTTPS", report.IntentDiff); Assert.Contains("\"enabled\": false", report.IntentDiff);
            Assert.Equal(baseline, store.GetPolicyRevision(revision.Revision)!.PolicyJson);
        }
        finally { Directory.Delete(path, true); }
    }
}

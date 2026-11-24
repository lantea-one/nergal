using System.Runtime.Versioning;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Core.Policy;

namespace Nergal.Web.Tests;

/// <summary>DNAT port selection retains translation/negation/state and validates exact database history.</summary>
[SupportedOSPlatform("linux")]
public sealed class DnatPortAuthoringTests
{
    private static FirewallPolicyBundle Bundle() => new(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, []),
        new(1, [new(IpFamily.IPv4, FilterProtocol.Tcp, new("198.51.100.10/32"), "192.0.2.2", 443, 8080, "wan0", new("203.0.113.0/24"), NegateSource: true, Enabled: false)], []));
    private static DnatRule Rule(string json) => PolicyBundleJsonCodec.DecodeBundle(json).Value!.Nat!.DnatRules[0]!;
    private static VisualDnatRuleInput Input() => new("ipv4", "tcp", "198.51.100.10/32", "192.0.2.2", null, 8080, "wan0", "203.0.113.0/24", "Edited dormant DNAT");

    /// <summary>Pinned fields survive ordinary edits; literal conflicts/protocol changes fail and explicit removal only clears the original port.</summary>
    [Fact]
    public void Draft_RetainsPinsAndAllTranslationIntent()
    {
        var reference = new PolicyObjectReference(Guid.NewGuid(), 1, new("web_ports", ReusableObjectKind.Port, "", ["443", "8443"]));
        var original = PolicyBundleJsonCodec.EncodeBundle(Bundle());
        Assert.True(PolicyObjectAuthoring.TrySet(original, 0, "ports", reference, out var attached, out _, "dnat"));
        Assert.True(PolicyAuthoringService.TryUpdateDnatRule(attached!, 0, Input(), out var edited, out _));
        var rule = Rule(edited!); Assert.Equal(reference, rule.OriginalPortObject); Assert.Equal(8080, rule.TranslatedPort); Assert.False(rule.Enabled); Assert.True(rule.NegateSource);
        Assert.False(PolicyAuthoringService.TryUpdateDnatRule(attached!, 0, Input() with { OriginalPort = 22 }, out _, out _));
        Assert.False(PolicyAuthoringService.TryUpdateDnatRule(attached!, 0, Input() with { Protocol = "any" }, out _, out _));
        Assert.False(PolicyObjectAuthoring.TrySet(attached!, 0, "source", reference, out _, out _, "dnat"));
        Assert.True(PolicyObjectAuthoring.TrySet(edited!, 0, "ports", null, out var removed, out _, "dnat"));
        var cleared = Rule(removed!); Assert.Null(cleared.OriginalPortObject); Assert.Null(cleared.OriginalPort); Assert.Null(cleared.OriginalPorts);
        Assert.Equal(rule with { OriginalPortObject = null }, cleared);
        Assert.True(PolicyAuthoringService.TryUpdateDnatRule(original, 0, Input() with { OriginalPorts = "443,8443" }, out var literal, out _));
        Assert.Equal(new[] { 443, 8443 }, Rule(literal!).OriginalPorts);
        Assert.False(PolicyAuthoringService.TryUpdateDnatRule(original, 0, Input() with { OriginalPorts = "443,443" }, out _, out _));
    }

    /// <summary>Saved usage and revisions retain old port snapshots; a forged later version cannot create another revision.</summary>
    [Fact]
    public void Database_BindsImmutableDnatPortVersion()
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var path = Path.Combine(Path.GetTempPath(), "ng-dnat-port-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var store = ControllerStateStore.Initialize(new(path)); var actor = ControllerActorIdentity.FromLocalAccount(Guid.NewGuid());
            var item = store.SaveReusableObject(null, 0, new("web_ports", ReusableObjectKind.Port, "", ["443", "8443"]), actor, NergalRoles.Administrator);
            Assert.True(PolicyObjectAuthoring.TrySet(PolicyBundleJsonCodec.EncodeBundle(Bundle()), 0, "ports", new(item.Id, 1, item.Content), out var json, out _, "dnat"));
            var report = PolicyAuthoringService.EvaluateDraft(json!, store); Assert.True(report.IsValid);
            var revision = store.SavePolicyRevision(json!, report.CandidateDigest!, actor, NergalRoles.Administrator);
            Assert.Equal("nat.dnatRules[0].originalPortObject", Assert.Single(store.ListPolicyObjectUsage(item.Id)).Path);
            store.SaveReusableObject(item.Id, 1, new("web_ports", ReusableObjectKind.Port, "Later", ["9443"]), actor, NergalRoles.Administrator);
            Assert.Equal(json, store.GetPolicyRevision(revision.Revision)!.PolicyJson);
            var forged = System.Text.Json.Nodes.JsonNode.Parse(json!)!; forged["nat"]!["dnatRules"]![0]!["originalPortObject"]!["version"] = 2;
            Assert.False(PolicyAuthoringService.EvaluateDraft(forged.ToJsonString(), store).IsValid); Assert.Single(store.ListPolicyRevisions());
        }
        finally { Directory.Delete(path, true); }
    }
}

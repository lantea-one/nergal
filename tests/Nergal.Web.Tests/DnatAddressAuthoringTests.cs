using System.Runtime.Versioning;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Core.Policy;

namespace Nergal.Web.Tests;

/// <summary>Guided DNAT address edits retain immutable pins, negation, ports and translation; SQL validates exact history.</summary>
[SupportedOSPlatform("linux")]
public sealed class DnatAddressAuthoringTests
{
    private static FirewallPolicyBundle Bundle(IpFamily family) => new(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept, []),
        new(1, [new(family, FilterProtocol.Tcp, new(family == IpFamily.IPv4 ? "198.51.100.10/32" : "2001:db8:2::10/128"),
            family == IpFamily.IPv4 ? "203.0.113.2" : "2001:db8:3::2", 443, 8080, "wan0", new(family == IpFamily.IPv4 ? "192.0.2.2/32" : "2001:db8:1::2/128"), NegateSource: true, NegateDestination: true, Enabled: false)], []));
    private static DnatRule Rule(string json) => PolicyBundleJsonCodec.DecodeBundle(json).Value!.Nat!.DnatRules[0]!;
    private static ReusableObjectContent Content(IpFamily family) => new("networks", family == IpFamily.IPv4 ? ReusableObjectKind.Ipv4 : ReusableObjectKind.Ipv6, "",
        family == IpFamily.IPv4 ? ["192.0.2.0/24", "198.51.100.0/24"] : ["2001:db8:1::/64", "2001:db8:2::/64"]);

    /// <summary>Both slots/families preserve pins during edits; destination removal is denied, source removal clears only that matcher/negation.</summary>
    [Theory]
    [InlineData(IpFamily.IPv4)]
    [InlineData(IpFamily.IPv6)]
    public void Draft_PreservesCompleteTranslationAndRequiredDestination(IpFamily family)
    {
        var reference = new PolicyObjectReference(Guid.NewGuid(), 1, Content(family)); var json = PolicyBundleJsonCodec.EncodeBundle(Bundle(family));
        foreach (var slot in new[] { "source", "destination" }) { Assert.True(PolicyObjectAuthoring.TrySet(json, 0, slot, reference, out var next, out _, "dnat")); json = next!; }
        var input = new VisualDnatRuleInput(family == IpFamily.IPv4 ? "ipv4" : "ipv6", "tcp", null, Rule(json).TranslatedAddress, 443, 8080, "wan0", null, "Retained addresses");
        Assert.True(PolicyAuthoringService.TryUpdateDnatRule(json, 0, input, out var edited, out _)); var rule = Rule(edited!);
        Assert.Equal(reference, rule.SourceObject); Assert.Equal(reference, rule.DestinationObject); Assert.True(rule.NegateSource); Assert.True(rule.NegateDestination); Assert.False(rule.Enabled);
        Assert.Equal(8080, rule.TranslatedPort); Assert.Equal(443, rule.OriginalPort);
        Assert.False(PolicyAuthoringService.TryUpdateDnatRule(json, 0, input with { Source = reference.Content.Entries[0] }, out _, out _));
        Assert.False(PolicyAuthoringService.TryUpdateDnatRule(json, 0, input with { OriginalDestination = reference.Content.Entries[0] }, out _, out _));
        Assert.False(PolicyObjectAuthoring.TrySet(json, 0, "destination", null, out _, out _, "dnat"));
        Assert.True(PolicyObjectAuthoring.TrySet(edited!, 0, "source", null, out var removed, out _, "dnat"));
        Assert.Equal(rule with { SourceObject = null, NegateSource = false }, Rule(removed!));
        Assert.True(PolicyAuthoringService.TryUpdateDnatRule(PolicyBundleJsonCodec.EncodeBundle(Bundle(family)), 0,
            input with { Source = string.Join(",", reference.Content.Entries), OriginalDestination = string.Join(",", reference.Content.Entries) }, out var literal, out _));
        Assert.Equal(2, Rule(literal!).SourcePrefixes!.Count); Assert.Equal(2, Rule(literal!).DestinationPrefixes!.Count);
    }

    /// <summary>Forged versions cannot replace immutable SQL address history or create another revision.</summary>
    [Fact]
    public void Database_BindsBothAddressSlotsAndUsage()
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var path = Path.Combine(Path.GetTempPath(), "ng-dnat-address-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try
        {
            var store = ControllerStateStore.Initialize(new(path)); var actor = ControllerActorIdentity.FromLocalAccount(Guid.NewGuid());
            var item = store.SaveReusableObject(null, 0, Content(IpFamily.IPv4), actor, NergalRoles.Administrator);
            var json = PolicyBundleJsonCodec.EncodeBundle(Bundle(IpFamily.IPv4));
            foreach (var slot in new[] { "source", "destination" }) { Assert.True(PolicyObjectAuthoring.TrySet(json, 0, slot, new(item.Id, 1, item.Content), out var next, out _, "dnat")); json = next!; }
            var report = PolicyAuthoringService.EvaluateDraft(json, store); Assert.True(report.IsValid);
            var revision = store.SavePolicyRevision(json, report.CandidateDigest!, actor, NergalRoles.Administrator); Assert.Equal(2, store.ListPolicyObjectUsage(item.Id).Count);
            store.SaveReusableObject(item.Id, 1, new("networks", ReusableObjectKind.Ipv4, "Later", ["203.0.113.10"]), actor, NergalRoles.Administrator);
            Assert.Equal(json, store.GetPolicyRevision(revision.Revision)!.PolicyJson);
            foreach (var field in new[] { "sourceObject", "destinationObject" })
            { var forged = System.Text.Json.Nodes.JsonNode.Parse(json)!; forged["nat"]!["dnatRules"]![0]![field]!["version"] = 2; Assert.False(PolicyAuthoringService.EvaluateDraft(forged.ToJsonString(), store).IsValid); }
            Assert.Single(store.ListPolicyRevisions());
        }
        finally { Directory.Delete(path, true); }
    }
}

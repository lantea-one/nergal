using System.Runtime.Versioning;
using Nergal.ControllerState;
using Nergal.Core.Controller;
using Nergal.Core.Identity;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web.Tests;

/// <summary>Pinned database references survive library edits and cannot be forged into saved revisions.</summary>
[SupportedOSPlatform("linux")]
public sealed class PolicyObjectBindingTests
{
    private static readonly string Actor = ControllerActorIdentity.FromLocalAccount(Guid.Parse("11111111-1111-4111-8111-111111111111"));
    private static FirewallPolicyBundle Bundle(PolicyObjectReference reference) => new(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
        [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, SourceObject: reference)]));

    /// <summary>Updating a shared object cannot change a saved policy's bytes, digest or reference version.</summary>
    [Fact]
    public void Revision_PinsOldContentsAndReportsHistoricalUsage()
    {
        WithStore(store =>
        {
            var item = store.SaveReusableObject(null, 0, new("clients", ReusableObjectKind.Ipv4, "", ["192.0.2.10"]), Actor, NergalRoles.Administrator);
            var bundle = Bundle(new(item.Id, item.Version, item.Content));
            var json = PolicyBundleJsonCodec.EncodeBundle(bundle); var digest = NftPolicyBundleCompiler.Compile(bundle).Digest!.Value;
            var revision = store.SavePolicyRevision(json, digest, Actor, NergalRoles.Administrator);
            store.SaveReusableObject(item.Id, 1, new("clients", ReusableObjectKind.Ipv4, "Changed", ["203.0.113.10"]), Actor, NergalRoles.Administrator);
            Assert.Equal(json, store.GetPolicyRevision(revision.Revision)!.PolicyJson);
            Assert.Empty(store.ValidatePolicyObjects(bundle));
            var use = Assert.Single(store.ListPolicyObjectUsage(item.Id)); Assert.Equal(1, use.ObjectVersion); Assert.Equal(revision.Revision, use.Revision);
            Assert.Equal(digest, NftPolicyBundleCompiler.Compile(PolicyBundleJsonCodec.DecodeBundle(json).Value!).Digest!.Value);
        });
    }

    /// <summary>Missing and modified snapshots fail both preview validation and transactional persistence.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Revision_DeniesMissingOrForgedSnapshots(bool forged)
    {
        WithStore(store =>
        {
            var item = store.SaveReusableObject(null, 0, new("clients", ReusableObjectKind.Ipv4, "", ["192.0.2.10"]), Actor, NergalRoles.Administrator);
            var reference = new PolicyObjectReference(forged ? item.Id : Guid.NewGuid(), 1, new("clients", ReusableObjectKind.Ipv4, "", ["203.0.113.10"]));
            var bundle = Bundle(reference); var json = PolicyBundleJsonCodec.EncodeBundle(bundle);
            Assert.Single(store.ValidatePolicyObjects(bundle));
            Assert.False(PolicyAuthoringService.EvaluateDraft(json, store).IsValid);
            Assert.Equal("object.referenceInvalid", Assert.Throws<ControllerStateException>(() => store.SavePolicyRevision(json, new string('a', 64), Actor, NergalRoles.Administrator)).Code);
            Assert.Empty(store.ListPolicyRevisions()); Assert.Single(store.ListAuditEntries());
        });
    }

    /// <summary>Draft attachment preserves MAC/negation and explicit removal does not leave a hidden matcher.</summary>
    [Fact]
    public void Authoring_AttachMoveAndRemoveKeepReferenceIntentExplicit()
    {
        var refContent = new ReusableObjectContent("clients", ReusableObjectKind.Ipv4, "", ["192.0.2.10"]);
        var reference = new PolicyObjectReference(Guid.NewGuid(), 1, refContent);
        var literal = new FirewallPolicyBundle(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
            [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, Source: new("198.51.100.0/24"), SourceMac: new("02:00:00:00:00:10"), NegateSource: true)]));
        Assert.True(PolicyObjectAuthoring.TrySet(PolicyBundleJsonCodec.EncodeBundle(literal), 0, "source", reference, out var attached, out _));
        var rule = PolicyBundleJsonCodec.DecodeBundle(attached!).Value!.Filter.Rules[0]!;
        Assert.Null(rule.Source); Assert.Equal(reference, rule.SourceObject); Assert.Equal(literal.Filter.Rules[0]!.SourceMac, rule.SourceMac); Assert.True(rule.NegateSource);
        var input = new VisualFilterRuleInput("input", "ipv4", "tcp", "accept", "", "", "443", "", "", "", "", Description: "Edited description");
        Assert.True(PolicyAuthoringService.TryUpdateFilterRule(attached!, 0, input, out var edited, out _));
        Assert.Equal(reference, PolicyBundleJsonCodec.DecodeBundle(edited!).Value!.Filter.Rules[0]!.SourceObject);
        var attachedBundle = PolicyBundleJsonCodec.DecodeBundle(attached!).Value!;
        var pair = new FirewallPolicyBundle(1, new(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
            [attachedBundle.Filter.Rules[0], new(IpFamily.IPv6, FilterProtocol.Any, FilterVerdict.Drop)]));
        Assert.True(PolicyAuthoringService.TryMoveFilterRule(PolicyBundleJsonCodec.EncodeBundle(pair), 0, 1, out var moved, out _));
        Assert.Equal(reference, PolicyBundleJsonCodec.DecodeBundle(moved!).Value!.Filter.Rules[1]!.SourceObject);
        Assert.True(PolicyObjectAuthoring.TrySet(attached!, 0, "source", null, out var removed, out _));
        var cleared = PolicyBundleJsonCodec.DecodeBundle(removed!).Value!.Filter.Rules[0]!;
        Assert.Null(cleared.SourceObject); Assert.Null(cleared.Source); Assert.False(cleared.NegateSource); Assert.NotNull(cleared.SourceMac);
        Assert.False(PolicyObjectAuthoring.TrySet(removed!, 0, "source", null, out _, out _));
        Assert.False(PolicyObjectAuthoring.TrySet(attached!, 99, "source", reference, out _, out _));
    }

    /// <summary>Auxiliary attachment pins the exact database version without changing primary intent or lifecycle state.</summary>
    [Fact]
    public void AuxiliaryReference_PreservesPrimaryAndReportsSavedUsage()
    {
        WithStore(store =>
        {
            var item = store.SaveReusableObject(null, 0, new("clients", ReusableObjectKind.Ipv4, "", ["192.0.2.10"]), Actor, NergalRoles.Administrator);
            var reference = new PolicyObjectReference(item.Id, item.Version, item.Content);
            var primary = Bundle(reference).Filter;
            var auxiliary = new FilterPolicy(2, FilterVerdict.Accept, FilterVerdict.Accept, FilterVerdict.Accept,
                [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Drop, Source: new("198.51.100.0/24"), NegateSource: true, SourceMac: new("02:00:00:00:00:01"), Enabled: false)]);
            var original = PolicyBundleJsonCodec.EncodeBundle(new(1, primary, auxiliaryFilter: new(-5, auxiliary)), indented: true);
            Assert.True(PolicyObjectAuthoring.TrySet(original, 0, "source", reference, out var updated, out _, "auxiliary"));
            var changed = PolicyBundleJsonCodec.DecodeBundle(updated!).Value!;
            Assert.Equal(primary.Rules[0], changed.Filter.Rules[0]);
            var rule = changed.AuxiliaryFilter!.Filter.Rules[0]!;
            Assert.False(rule.Enabled); Assert.True(rule.NegateSource); Assert.Equal(reference, rule.SourceObject);
            Assert.Equal("02:00:00:00:00:01", rule.SourceMac!.Value); Assert.Null(rule.Source);
            var report = PolicyAuthoringService.EvaluateDraft(updated!, store);
            Assert.True(report.IsValid);
            var saved = store.SavePolicyRevision(updated!, report.CandidateDigest!, Actor, NergalRoles.Administrator);
            Assert.Contains(store.ListPolicyObjectUsage(item.Id), u => u.Path == "auxiliaryFilter.filter.rules[0].sourceObject");
            store.SaveReusableObject(item.Id, 1, new("clients", ReusableObjectKind.Ipv4, "Updated", ["203.0.113.10"]), Actor, NergalRoles.Administrator);
            Assert.Equal(updated, store.GetPolicyRevision(saved.Revision)!.PolicyJson);
            Assert.True(PolicyObjectAuthoring.TrySet(updated!, 0, "source", null, out var removed, out _, "auxiliary"));
            var cleared = PolicyBundleJsonCodec.DecodeBundle(removed!).Value!;
            Assert.False(cleared.AuxiliaryFilter!.Filter.Rules[0]!.NegateSource); Assert.Null(cleared.AuxiliaryFilter.Filter.Rules[0]!.SourceObject);
            Assert.Equal(primary.Rules[0], cleared.Filter.Rules[0]);
            Assert.False(PolicyObjectAuthoring.TrySet(updated!, 0, "source", reference, out _, out _, "unknown"));
            Assert.False(PolicyObjectAuthoring.TrySet(PolicyBundleJsonCodec.EncodeBundle(new(1, primary)), 0, "source", reference, out _, out _, "auxiliary"));
        });
    }

    /// <summary>Reference attachment never normalizes unknown filter schema versions to a known schema.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(99)]
    public void Reference_RejectUnknownSchema(int schema)
    {
        var reference = new PolicyObjectReference(Guid.NewGuid(), 1, new("clients", ReusableObjectKind.Ipv4, "", ["192.0.2.10"]));
        var json = PolicyBundleJsonCodec.EncodeBundle(new(1, new(schema, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
            [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept)])));
        Assert.False(PolicyObjectAuthoring.TrySet(json, 0, "source", reference, out _, out _));
    }

    private static void WithStore(Action<ControllerStateStore> action)
    {
        if (!OperatingSystem.IsLinux()) { return; }
        var path = Path.Combine(Path.GetTempPath(), "ng-reference-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        try { action(ControllerStateStore.Initialize(new(path))); } finally { Directory.Delete(path, true); }
    }
}

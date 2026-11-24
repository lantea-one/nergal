using System.Text.Json.Nodes;
using Nergal.Core.Controller;
using Nergal.Core.Policy;
using Nergal.Nftables;
using Nergal.Testing;

namespace Nergal.Core.Tests;

/// <summary>Native set contents, ownership handles and lookup edges must survive independently of controller metadata.</summary>
public sealed class NativeStaticSetTests
{
    private static readonly NftTableIdentity Identity = new(Guid.Parse("00000000-0000-0000-0000-000000000010"), Guid.Parse("00000000-0000-0000-0000-000000000020"));
    private static PolicyObjectReference Ports(bool native = true, string[]? entries = null) => new(Guid.Parse("00000000-0000-0000-0000-000000000031"), 1,
        new("services", ReusableObjectKind.Port, "Immutable service ports", entries ?? ["80", "443"]), native);
    private static FilterPolicy Policy(PolicyObjectReference reference, bool enabled = true) => new(2, FilterVerdict.Drop, FilterVerdict.Accept, FilterVerdict.Accept,
        [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, DestinationPortObject: reference, Enabled: enabled),
         new(IpFamily.IPv6, FilterProtocol.Tcp, FilterVerdict.Accept, DestinationPortObject: reference, Enabled: enabled)]);

    /// <summary>Two rules share one static definition, including singleton lists, without changing transport restrictions.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void SharedReferencesHaveOneDefinitionAndTwoLookups(bool singleton)
    {
        var compiled = NftFilterCompiler.Compile(Policy(Ports(entries: singleton ? ["443"] : null)));
        Assert.True(compiled.IsSuccess);
        Assert.Single(compiled.Candidate!.Split('\n'), l => l.StartsWith("add set ", StringComparison.Ordinal));
        Assert.Equal(2, compiled.Candidate.Split('\n').Count(l => l.Contains("dport @nergal_obj_", StringComparison.Ordinal)));
        Assert.Contains("flags constant;", compiled.Candidate);
    }

    /// <summary>Legacy references retain their canonical bytes, while an explicit native choice survives every scope.</summary>
    [Fact]
    public void ProjectionChoiceIsVersionedAndLegacyJsonOmitsTheNewFlag()
    {
        var legacy = new FirewallPolicyBundle(1, Policy(Ports(false)));
        var json = PolicyBundleJsonCodec.EncodeBundle(legacy);
        Assert.DoesNotContain("nativeSet", json);
        Assert.DoesNotContain("add set ", NftFilterCompiler.Compile(legacy.Filter).Candidate);
        var bundle = Sample();
        var encoded = PolicyBundleJsonCodec.EncodeBundle(bundle);
        Assert.Contains("\"nativeSet\":", encoded);
        Assert.Equal(encoded, PolicyBundleJsonCodec.EncodeBundle(PolicyBundleJsonCodec.DecodeBundle(encoded).Value!));
        Assert.NotEqual(Ports(), Ports(false));
    }

    /// <summary>Strings and unknown reference properties cannot silently select a weaker projection.</summary>
    [Theory]
    [InlineData("\"true\"")]
    [InlineData("null")]
    [InlineData("1")]
    public void MalformedNativeChoiceIsRejected(string invalid)
    {
        var root = JsonNode.Parse(PolicyBundleJsonCodec.EncodeBundle(new(1, Policy(Ports()))))!;
        root["filter"]!["rules"]![0]!["destinationPortObject"]!["nativeSet"] = JsonNode.Parse(invalid);
        Assert.False(PolicyBundleJsonCodec.DecodeBundle(root.ToJsonString()).IsSuccess);
    }

    /// <summary>Dormant rules retain the choice but allocate no runtime object; invalid dormant conflicts still fail.</summary>
    [Fact]
    public void DormantReferencesDoNotCreateUnusedSetsOrBypassValidation()
    {
        var policy = Policy(Ports(), false);
        Assert.DoesNotContain("add set ", NftFilterCompiler.Compile(policy).Candidate);
        var rules = policy.Rules.Select(r => r! with { DestinationPort = 80 });
        Assert.False(NftFilterCompiler.Compile(new(2, FilterVerdict.Drop, FilterVerdict.Accept, FilterVerdict.Accept, rules)).IsSuccess);
    }

    /// <summary>One native identity/version cannot mean two contents, even if one use is disabled.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ConflictingEmbeddedVersionsAreRejected(bool enabled)
    {
        var policy = new FilterPolicy(2, FilterVerdict.Drop, FilterVerdict.Accept, FilterVerdict.Accept,
            [new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, DestinationPortObject: Ports()),
             new(IpFamily.IPv6, FilterProtocol.Tcp, FilterVerdict.Accept, DestinationPortObject: Ports(entries: ["8443"]), Enabled: enabled)]);
        Assert.Contains(NftFilterCompiler.Compile(policy).Diagnostics, d => d.Code == "object.nativeSnapshotConflict");
    }

    /// <summary>Real kernel echo and independent complete listings reconstruct all tables and regenerate exact native artifacts.</summary>
    [Fact]
    public void KernelEchoAndListingsPreserveNamedDefinitionsAndReferences()
    {
        var echo = NftTableObservation.ParseBundleReplacementEcho(Read("echo"), Identity, true, true, true);
        Assert.True(echo.IsSuccess, echo.ErrorCode);
        var primary = NftTableObservation.Parse(Read("filter"));
        var nat = NftNatTableObservation.Parse(Read("nat"));
        var bridge = NftBridgeTableObservation.Parse(Read("bridge"));
        var auxiliary = NftAuxiliaryTableObservation.Parse(Read("aux"));
        Assert.True(primary.IsSuccess, primary.ErrorCode); Assert.True(nat.IsSuccess, nat.ErrorCode); Assert.True(bridge.IsSuccess, bridge.ErrorCode); Assert.NotNull(auxiliary);
        var listed = NftTableObservation.Combine(primary.Observation!, nat.Observation, bridge.Observation, auxiliary);
        Assert.Equal(echo.Observation!.StateDigest, listed.StateDigest);
        Assert.Equal(NftPolicyBundleCompiler.Compile(Sample(), Identity).Candidate, NftPolicyBundleCompiler.Compile(listed.Bundle, Identity).Candidate);
        Assert.All(listed.Policy.Rules, r => Assert.True(r!.DestinationPortObject!.NativeSet));
    }

    /// <summary>Partial, unknown or ambiguous native definitions cannot back an ownership receipt.</summary>
    [Theory]
    [InlineData("missing-elements")]
    [InlineData("empty-elements")]
    [InlineData("duplicate-elements")]
    [InlineData("missing-constant")]
    [InlineData("null-flag")]
    [InlineData("unknown-field")]
    [InlineData("unknown-wrapper")]
    [InlineData("wrong-type")]
    [InlineData("invalid-name")]
    [InlineData("colliding-handle")]
    [InlineData("missing-definition")]
    [InlineData("unknown-lookup")]
    [InlineData("orphan-definition")]
    public void UnsafeNativeObjectsAreDenied(string mutation)
    {
        var root = JsonNode.Parse(Read("filter"))!;
        var objects = root["nftables"]!.AsArray();
        var definition = objects.Single(i => i?["set"] is not null)!["set"]!;
        var rule = objects.First(i => i?["rule"] is not null)!["rule"]!;
        switch (mutation)
        {
            case "missing-elements": definition.AsObject().Remove("elem"); break;
            case "empty-elements": definition["elem"] = new JsonArray(); break;
            case "duplicate-elements": definition["elem"]!.AsArray().Add(19001); break;
            case "missing-constant": definition["flags"] = new JsonArray(); break;
            case "null-flag": definition["flags"] = new JsonArray((JsonNode?)null); break;
            case "unknown-field": definition["timeout"] = 10; break;
            case "unknown-wrapper": objects.Single(i => i?["set"] is not null)!["unknown"] = true; break;
            case "wrong-type": definition["type"] = "ipv4_addr"; break;
            case "invalid-name": definition["name"] = "nergal_obj_bad"; break;
            case "colliding-handle": definition["handle"] = 1; break;
            case "missing-definition": objects.Remove(objects.Single(i => i?["set"] is not null)); break;
            case "unknown-lookup": rule["expr"]![1]!["match"]!["right"] = "@foreign"; break;
            case "orphan-definition": var extra = definition.DeepClone(); extra["name"] = "nergal_obj_00000000000000000000000000000099_1_p"; extra["handle"] = 99; objects.Insert(4, new JsonObject { ["set"] = extra }); break;
        }
        Assert.False(NftTableObservation.Parse(root.ToJsonString()).IsSuccess);
    }

    /// <summary>Equal expanded values do not hide a changed lookup edge or recreated set handle.</summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void NativeIdentityAndLookupBindingArePartOfTheReceipt(bool handleOnly)
    {
        var root = JsonNode.Parse(Read("filter"))!;
        var objects = root["nftables"]!.AsArray();
        var definition = objects.Single(i => i?["set"] is not null)!["set"]!;
        if (handleOnly) { definition["handle"] = 100; }
        else
        {
            var alias = definition.DeepClone(); alias["name"] = "nergal_obj_00000000000000000000000000000099_1_p"; alias["handle"] = 99;
            objects.Insert(4, new JsonObject { ["set"] = alias });
            objects.First(i => i?["rule"] is not null)!["rule"]!["expr"]![1]!["match"]!["right"] = "@nergal_obj_00000000000000000000000000000099_1_p";
        }
        var changed = NftTableObservation.Parse(root.ToJsonString());
        Assert.True(changed.IsSuccess, changed.ErrorCode);
        Assert.NotEqual(NftTableObservation.Parse(Read("filter")).Observation!.StateDigest, changed.Observation!.StateDigest);
    }

    /// <summary>Per-set replies must match the requested native definition and handle exactly.</summary>
    [Theory]
    [InlineData("valid")]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("handle")]
    [InlineData("scope")]
    [InlineData("partial")]
    [InlineData("unknown-wrapper")]
    public void CompleteCollectionRequiresEveryBoundSet(string mutation)
    {
        var root = JsonNode.Parse(Read("filter"))!;
        var objects = root["nftables"]!.AsArray();
        var definition = objects.Single(i => i?["set"] is not null)!["set"]!;
        var reply = new JsonObject { ["nftables"] = new JsonArray(objects[0]!.DeepClone(), new JsonObject { ["set"] = definition.DeepClone() }) };
        definition.AsObject().Remove("elem");
        Assert.Single(NftStaticSetCollection.Names(root.ToJsonString(), "inet", "nergal_filter"));
        if (mutation == "unknown-wrapper") { objects.Single(i => i?["set"] is not null)!["unknown"] = true; }
        var set = reply["nftables"]![1]!["set"]!;
        if (mutation == "handle") { set["handle"] = 100; }
        if (mutation == "scope") { set["table"] = "foreign"; }
        if (mutation == "partial") { set.AsObject().Remove("elem"); }
        var replies = mutation == "missing" ? Array.Empty<string>() : mutation == "duplicate" ? new[] { reply.ToJsonString(), reply.ToJsonString() } : [reply.ToJsonString()];
        if (mutation == "valid")
        {
            var complete = NftStaticSetCollection.Complete(root.ToJsonString(), "inet", "nergal_filter", replies);
            Assert.Equal(NftTableObservation.Parse(Read("filter")).Observation!.StateDigest, NftTableObservation.Parse(complete).Observation!.StateDigest);
        }
        else { Assert.Throws<ArgumentException>(() => NftStaticSetCollection.Complete(root.ToJsonString(), "inet", "nergal_filter", replies)); }
    }

    /// <summary>A valid but oversized list graph is refused before it can create an unobservable applied candidate.</summary>
    [Fact]
    public void OversizedNativeEchoIsRejectedBeforeApply()
    {
        var rules = Enumerable.Range(1, 8).Select(index => new FilterRule(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept,
            DestinationPortObject: new(new Guid(index, 0, 0, new byte[8]), 1,
                new("services_" + index, ReusableObjectKind.Port, "", Enumerable.Range(index * 100, 64).Select(p => p.ToString(System.Globalization.CultureInfo.InvariantCulture))), true)));
        var result = NftFilterCompiler.Compile(new(2, FilterVerdict.Drop, FilterVerdict.Accept, FilterVerdict.Accept, rules));
        Assert.Null(result.Candidate);
        Assert.Contains(result.Diagnostics, d => d.Code == "object.nativeObservationTooLarge");
    }

    /// <summary>Omitted echo elements require matching creation handles and a complete listing equal to protected intent.</summary>
    [Theory]
    [InlineData("valid")]
    [InlineData("echo-handle")]
    [InlineData("listing-handle")]
    [InlineData("echo-value")]
    [InlineData("missing-definition")]
    [InlineData("missing-listing")]
    [InlineData("wrong-artifact")]
    [InlineData("definition-wrapper")]
    [InlineData("definition-command")]
    [InlineData("element-wrapper")]
    [InlineData("missing-all-definitions")]
    public void CreationCompletionCannotAdoptUnprovenDefinitionsOrContents(string mutation)
    {
        var echo = JsonNode.Parse(Read("echo"))!;
        var items = echo["nftables"]!.AsArray();
        var firstSet = items.First(i => i?["add"]?["set"] is not null)!["add"]!["set"]!;
        var originals = items.Where(i => i?["add"]?["element"] is not null).ToArray();
        foreach (var element in originals) { items.Remove(element); }
        if (mutation == "echo-handle") { firstSet["handle"] = 100; }
        if (mutation == "definition-wrapper") { items.First(i => i?["add"]?["set"] is not null)!["unknown"] = true; }
        if (mutation == "definition-command") { items.First(i => i?["add"]?["set"] is not null)!["add"]!["unknown"] = true; }
        if (mutation == "element-wrapper") { var extra = originals[0]!.DeepClone(); extra["unknown"] = true; items.Add(extra); }
        if (mutation == "missing-all-definitions") { foreach (var item in items.Where(i => i?["add"]?["set"] is not null).ToArray()) { items.Remove(item); } }
        if (mutation == "echo-value")
        {
            var wrong = originals[0]!.DeepClone(); wrong["add"]!["element"]!["elem"]!["set"]![0] = 65535;
            items.Add(wrong);
        }
        if (mutation == "missing-definition") { items.Remove(items.First(i => i?["add"]?["set"] is not null)); }
        var filter = JsonNode.Parse(Read("filter"))!;
        if (mutation == "listing-handle") { filter["nftables"]!.AsArray().Single(i => i?["set"] is not null)!["set"]!["handle"] = 100; }
        var listings = new[] { filter.ToJsonString(), Read("nat"), Read("bridge"), Read("aux") };
        if (mutation == "missing-listing") { listings = listings[..3]; }
        var expected = NftPolicyBundleCompiler.Compile(Sample(), Identity).Candidate!;
        if (mutation == "wrong-artifact") { expected += "\n"; }
        if (mutation != "valid")
        { Assert.Throws<ArgumentException>(() => NftStaticSetCreationEvidence.Complete(echo.ToJsonString(), listings, expected)); return; }
        Assert.False(NftTableObservation.ParseBundleReplacementEcho(echo.ToJsonString(), Identity, true, true, true).IsSuccess);
        var completed = NftStaticSetCreationEvidence.Complete(echo.ToJsonString(), listings, expected);
        var actual = NftTableObservation.ParseBundleReplacementEcho(completed, Identity, true, true, true);
        Assert.True(actual.IsSuccess, actual.ErrorCode);
        Assert.Equal(NftTableObservation.ParseBundleReplacementEcho(Read("echo"), Identity, true, true, true).Observation!.StateDigest, actual.Observation!.StateDigest);
    }

    private static FirewallPolicyBundle Sample() => RouterPolicySamples.WithNativeSetReferences(RouterPolicySamples.WithTransportReferences(RouterPolicySamples.WithPostroutingAddressReferences(RouterPolicySamples.WithBridgeAddressReferences(RouterPolicySamples.WithDnatAddressReferences(RouterPolicySamples.AuxiliaryAcceptance())))));
    private static string Read(string name)
    {
        var assembly = typeof(NativeStaticSetTests).Assembly;
        using var reader = new StreamReader(assembly.GetManifestResourceStream(assembly.GetManifestResourceNames().Single(n => n.EndsWith("native-static-" + name + ".json", StringComparison.Ordinal)))!);
        return reader.ReadToEnd();
    }
}

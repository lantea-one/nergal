using System.Text.Json.Nodes;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Complete receipts must detect auxiliary drift even when the primary filter is unchanged.</summary>
public sealed class CompleteBundleObservationTests
{
    private static readonly NftTableIdentity Identity = new(
        Guid.Parse("00000000-0000-0000-0000-000000000010"), Guid.Parse("00000000-0000-0000-0000-000000000020"));

    /// <summary>Recorded synthetic native listings preserve the extended bridge and early inet echo fingerprints.</summary>
    [Fact]
    public void NativeAuxiliaryListings_MatchCompleteCreationEcho()
    {
        var echo = Parse(Read("bundle-echo.json"));
        var bridge = NftBridgeTableObservation.Parse(Read("bridge-list.json"));
        var auxiliary = NftAuxiliaryTableObservation.Parse(Read("aux-list.json"));
        Assert.True(bridge.IsSuccess, bridge.ErrorCode);
        Assert.NotNull(auxiliary);
        Assert.Equal(echo.Bridge!.StateDigest, bridge.Observation!.StateDigest);
        Assert.Equal(echo.Auxiliary!.StateDigest, auxiliary!.StateDigest);
    }

    /// <summary>Every auxiliary handle participates in the receipt; copying ownership comments cannot hide recreation.</summary>
    [Theory]
    [InlineData("nergal_nat", "table")]
    [InlineData("nergal_nat", "chain")]
    [InlineData("nergal_nat", "rule")]
    [InlineData("nergal_bridge", "table")]
    [InlineData("nergal_bridge", "chain")]
    [InlineData("nergal_bridge", "rule")]
    [InlineData("nergal_aux", "table")]
    [InlineData("nergal_aux", "chain")]
    [InlineData("nergal_aux", "rule")]
    public void AuxiliaryHandleChange_ChangesCompleteReceipt(string table, string kind)
    {
        var json = Read("bundle-echo.json");
        var expected = Parse(json);
        var node = JsonNode.Parse(json)!;
        var value = node["nftables"]!.AsArray().Select(item => item?[kind == "table" ? "create" : "add"]?[kind])
            .First(item => item is not null && (string?)item[kind == "table" ? "name" : "table"] == table)!;
        value["handle"] = 10000;
        var changed = Parse(node.ToJsonString());
        Assert.Equal(expected.TableHandle, changed.TableHandle);
        Assert.NotEqual(expected.StateDigest, changed.StateDigest);
        Assert.Equal(NftPolicyBundleCompiler.Compile(expected.Bundle, Identity).Candidate,
            NftPolicyBundleCompiler.Compile(changed.Bundle, Identity).Candidate);
    }

    /// <summary>Unknown syntax, different ownership, unexpected scope and incomplete echoes never yield partial authority.</summary>
    [Theory]
    [InlineData("unknownRule")]
    [InlineData("missingTable")]
    [InlineData("wrongOwner")]
    [InlineData("cycle")]
    [InlineData("auxPriority")]
    public void IncompleteOrUnknownComponent_DeniesWholeEcho(string mutation)
    {
        var node = JsonNode.Parse(Read("bundle-echo.json"))!;
        var items = node["nftables"]!.AsArray();
        var bridgeRule = items.Select(i => i?["add"]?["rule"]).First(i => (string?)i?["table"] == "nergal_bridge")!;
        switch (mutation)
        {
            case "unknownRule": bridgeRule["expr"]!.AsArray().Insert(0, new JsonObject { ["counter"] = new JsonObject() }); break;
            case "missingTable": items.RemoveAt(items.Count - 1); items.RemoveAt(items.Count - 1); break;
            case "wrongOwner": items.Select(i => i?["create"]?["table"]).First(i => (string?)i?["name"] == "nergal_bridge")!["comment"] = new NftTableIdentity(Guid.NewGuid(), Identity.ResourceId).Comment; break;
            case "cycle": bridgeRule["expr"]!.AsArray()[^1]!["jump"]!["target"] = "forward"; break;
            case "auxPriority": items.Select(i => i?["add"]?["chain"]).First(i => (string?)i?["table"] == "nergal_aux")!["prio"] = -6; break;
        }
        Assert.False(NftTableObservation.ParseBundleReplacementEcho(node.ToJsonString(), Identity, true, true, true).IsSuccess);
    }

    /// <summary>Auxiliary semantic drift affects the complete fingerprint, not the primary table receipt alone.</summary>
    [Fact]
    public void AuxiliaryRuleChange_ChangesCompleteArtifactAndReceipt()
    {
        var node = JsonNode.Parse(Read("bundle-echo.json"))!;
        var expected = Parse(node.ToJsonString());
        var rule = node["nftables"]!.AsArray().Select(i => i?["add"]?["rule"]).First(i => (string?)i?["table"] == "nergal_aux")!;
        rule["expr"]!.AsArray()[^1] = new JsonObject { ["accept"] = null };
        var changed = Parse(node.ToJsonString());
        Assert.Equal(NftFilterCompiler.Compile(expected.Policy, Identity).Candidate, NftFilterCompiler.Compile(changed.Policy, Identity).Candidate);
        Assert.NotEqual(expected.StateDigest, changed.StateDigest);
        Assert.NotEqual(NftPolicyBundleCompiler.Compile(expected.Bundle, Identity).Candidate, NftPolicyBundleCompiler.Compile(changed.Bundle, Identity).Candidate);
    }

    private static NftTableObservation Parse(string json)
    {
        var result = NftTableObservation.ParseBundleReplacementEcho(json, Identity, true, true, true);
        Assert.True(result.IsSuccess, result.ErrorCode);
        return result.Observation!;
    }
    private static string Read(string filename)
    {
        var assembly = typeof(CompleteBundleObservationTests).Assembly;
        using var stream = assembly.GetManifestResourceStream(assembly.GetManifestResourceNames().Single(n => n.EndsWith(filename, StringComparison.Ordinal)))!;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}

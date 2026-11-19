using System.Text.Json.Nodes;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Core.Tests;

/// <summary>Verifies that familiar names/comments cannot replace expected context, handle and complete state bindings.</summary>
public sealed class NftResourceReceiptTests
{
    private static readonly Guid Owner = Guid.Parse("00000000-0000-0000-0000-000000000001");
    private static readonly Guid Resource = Guid.Parse("00000000-0000-0000-0000-000000000002");
    private static readonly Guid Boot = Guid.Parse("00000000-0000-0000-0000-000000000003");
    private static readonly Guid Other = Guid.Parse("00000000-0000-0000-0000-000000000004");
    private const string Json = """
        {"nftables":[
          {"metainfo":{"version":"fixture","release_name":"fixture","json_schema_version":1}},
          {"table":{"family":"inet","name":"nergal_filter","handle":7,"comment":"nergal:v1:00000000000000000000000000000001:00000000000000000000000000000002"}},
          {"chain":{"family":"inet","table":"nergal_filter","name":"input","handle":9,"type":"filter","hook":"input","prio":0,"policy":"accept"}}
        ]}
        """;

    /// <summary>Only typed UUIDs enter the native marker, and marker bytes participate in candidate identity.</summary>
    [Fact]
    public void Compiler_TaggedCandidateRemainsCreateOnlyAndContentBound()
    {
        var identity = new NftTableIdentity(Owner, Resource);
        var policy = new FilterPolicy(1, FilterVerdict.Drop, []);
        var tagged = NftFilterCompiler.Compile(policy, identity);
        Assert.True(tagged.IsSuccess);
        Assert.StartsWith("create table inet nergal_filter { comment \"" + identity.Comment + "\"; }\n", tagged.Candidate);
        Assert.NotEqual(NftFilterCompiler.Compile(policy).Digest, tagged.Digest);
        Assert.NotEqual(tagged.Digest, NftFilterCompiler.Compile(policy, new(Owner, Other)).Digest);
        Assert.Equal(tagged.Candidate, NftFilterCompiler.Compile(policy, new(Owner, Resource)).Candidate);
        Assert.DoesNotContain("delete ", tagged.Candidate!);
        Assert.DoesNotContain("flush ", tagged.Candidate!);
        Assert.Null(NftFilterCompiler.Compile(new(99, FilterVerdict.Drop, []), identity).Candidate);
    }

    /// <summary>Empty enrollment identities and missing objects cannot be mistaken for valid bindings.</summary>
    [Fact]
    public void Contracts_RejectMissingIdentityContextAndObjects()
    {
        Assert.Throws<ArgumentException>(() => new NftTableIdentity(Guid.Empty, Resource));
        Assert.Throws<ArgumentException>(() => new NftTableIdentity(Owner, Guid.Empty));
        Assert.Throws<ArgumentNullException>(() => NftFilterCompiler.Compile(new(1, FilterVerdict.Drop, []), null!));
        Assert.Throws<ArgumentNullException>(() => NftFilterCompiler.Compile(null!, new(Owner, Resource)));
        Assert.Throws<ArgumentNullException>(() => NftTableObservation.Parse(null!));
        var actual = Observe();
        Assert.Throws<ArgumentException>(() => new NftTableReceipt(Guid.Empty, 42, actual.Identity, 7, actual.StateDigest));
        Assert.Throws<ArgumentOutOfRangeException>(() => new NftTableReceipt(Boot, 0, actual.Identity, 7, actual.StateDigest));
        Assert.Throws<ArgumentOutOfRangeException>(() => new NftTableReceipt(Boot, 42, actual.Identity, 0, actual.StateDigest));
        Assert.Throws<ArgumentNullException>(() => new NftTableReceipt(Boot, 42, null!, 7, actual.StateDigest));
        Assert.Throws<ArgumentNullException>(() => new NftTableReceipt(Boot, 42, actual.Identity, 7, null!));
        Assert.Throws<ArgumentNullException>(() => NftReceiptVerifier.Verify(null!, actual, Boot, 42));
        Assert.Throws<ArgumentNullException>(() => NftReceiptVerifier.Verify(Receipt(actual), null!, Boot, 42));
    }

    /// <summary>Complete native observations compare successfully only against the matching expected receipt.</summary>
    [Fact]
    public void Observation_ParsesImmutableTypedState()
    {
        var node = JsonNode.Parse(Json)!;
        var observation = NftTableObservation.Parse(node.ToJsonString()).Observation!;
        Assert.Equal(new(Owner, Resource), observation.Identity);
        Assert.Equal(7UL, observation.TableHandle);
        Assert.Equal(9UL, observation.ChainHandle);
        Assert.Equal(FilterVerdict.Accept, observation.DefaultVerdict);
        Assert.True(NftReceiptVerifier.Verify(Receipt(observation), observation, Boot, 42).IsMatch);
        // Persisted schema-2 receipts for empty chains must survive this extension.
        Assert.Equal("34ab8b04c9ef48d4fa0f057bb7ce700c1bb190cee6fdb006e1d45030687ee0c5", observation.StateDigest.Value);
        var digest = observation.StateDigest;
        Item(node, "chain")["policy"] = "drop";
        Assert.Equal(FilterVerdict.Accept, observation.DefaultVerdict);
        Assert.Equal(digest, observation.StateDigest);
        Assert.NotEqual(digest, NftTableObservation.Parse(node.ToJsonString()).Observation!.StateDigest);
    }

    private const string FamilyRule = """
        {"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":10,"expr":[
        {"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"drop":null}]}}
        """;

    /// <summary>Both native order and rule handles bind the observation, independently of equivalent JSON presentation.</summary>
    [Fact]
    public void FamilyRules_PreserveOrderHandlesAndExactBaseline()
    {
        var node = JsonNode.Parse(Json)!;
        var items = node["nftables"]!.AsArray();
        var first = JsonNode.Parse(FamilyRule)!;
        var second = JsonNode.Parse(FamilyRule.Replace("ipv4", "ipv6").Replace("10", "11").Replace("drop", "accept"))!;
        items.Add(first);
        items.Add(second);
        NftTableObservation Read() => NftTableObservation.Parse(node.ToJsonString()).Observation!;
        var original = Read();
        Assert.Equal([new FilterRule(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Drop),
            new FilterRule(IpFamily.IPv6, FilterProtocol.Any, FilterVerdict.Accept)], original.Policy.Rules);
        items.RemoveAt(3);
        items.Add(first);
        Assert.NotEqual(original.StateDigest, Read().StateDigest);
        items.RemoveAt(4);
        items.Insert(3, first);
        Assert.Equal(original.StateDigest, Read().StateDigest);
        first["rule"]!["handle"] = 11;
        Reject(node.ToJsonString(), "observation.handle");
        first["rule"]!["handle"] = 15;
        Assert.NotEqual(original.StateDigest, Read().StateDigest);
    }

    /// <summary>Malformed scope, shared handles, additional effects and unfamiliar matching expressions reject the entire snapshot.</summary>
    [Theory]
    [InlineData("10", "9", "observation.handle")]
    [InlineData("10", "0", "observation.handle")]
    [InlineData("inet", "ip", "observation.scope")]
    [InlineData("nfproto", "l4proto", "observation.rule")]
    [InlineData("==", "!=", "observation.rule")]
    [InlineData("ipv4", "other", "observation.rule")]
    [InlineData("null", "false", "observation.rule")]
    [InlineData("drop", "reject", "observation.rule")]
    [InlineData("{\"drop\":null}", "{\"counter\":null},{\"drop\":null}", "observation.rule")]
    public void FamilyRules_RejectUnsupportedSemantics(string from, string to, string code)
    {
        var node = JsonNode.Parse(Json)!;
        node["nftables"]!.AsArray().Add(JsonNode.Parse(FamilyRule.Replace(from, to)));
        Reject(node.ToJsonString(), code);
    }

    /// <summary>Property presentation and tool version strings do not change enforcement identity.</summary>
    [Fact]
    public void Observation_PropertyOrderAndToolVersionAreNotEnforcementDrift()
    {
        var node = JsonNode.Parse(Json)!;
        Item(node, "metainfo")["version"] = "another-version";
        Item(node, "metainfo")["release_name"] = "another-release";
        var table = Item(node, "table");
        var name = table["name"]!.DeepClone();
        table.Remove("name");
        table.Add("name", name);
        Assert.Equal(Observe().StateDigest, NftTableObservation.Parse(node.ToJsonString()).Observation!.StateDigest);
    }

    /// <summary>Unsupported objects cannot be dropped from an apparently complete ownership observation.</summary>
    [Theory]
    [InlineData("rule")]
    [InlineData("set")]
    [InlineData("chain")]
    [InlineData("counter")]
    public void Observation_ExtraObjectsReject(string kind)
    {
        var node = JsonNode.Parse(Json)!;
        node["nftables"]!.AsArray().Add(new JsonObject { [kind] = new JsonObject() });
        Reject(node.ToJsonString(), "observation.unsupportedObjects");
    }

    /// <summary>Unknown fields fail rather than silently discarding flags, comments or interface restrictions.</summary>
    [Theory]
    [InlineData("table", "flags")]
    [InlineData("table", "unexpected")]
    [InlineData("chain", "dev")]
    [InlineData("chain", "comment")]
    public void Observation_UnknownFieldsReject(string kind, string field)
    {
        var node = JsonNode.Parse(Json)!;
        Item(node, kind)[field] = "unsupported";
        Reject(node.ToJsonString(), "observation.fields");
    }

    /// <summary>Different hooks, families, names and decisions cannot masquerade as the supported input slice.</summary>
    [Theory]
    [InlineData("table", "family", "ip", "observation.scope")]
    [InlineData("table", "name", "foreign", "observation.scope")]
    [InlineData("chain", "family", "ip6", "observation.scope")]
    [InlineData("chain", "table", "foreign", "observation.scope")]
    [InlineData("chain", "name", "forward", "observation.scope")]
    [InlineData("chain", "type", "nat", "observation.scope")]
    [InlineData("chain", "hook", "output", "observation.scope")]
    [InlineData("chain", "policy", "reject", "observation.policy")]
    [InlineData("table", "comment", "foreign marker", "observation.identity")]
    public void Observation_UnsupportedValuesReject(string kind, string field, string value, string code)
    {
        var node = JsonNode.Parse(Json)!;
        Item(node, kind)[field] = value;
        Reject(node.ToJsonString(), code);
    }

    /// <summary>Markers require canonical lowercase UUIDs, nonempty identities and the supported marker version.</summary>
    [Theory]
    [InlineData("nergal:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:00000000000000000000000000000002")]
    [InlineData("nergal:v1:00000000000000000000000000000000:00000000000000000000000000000002")]
    [InlineData("nergal:v2:00000000000000000000000000000001:00000000000000000000000000000002")]
    public void Observation_NoncanonicalMarkerRejects(string marker)
    {
        var node = JsonNode.Parse(Json)!;
        Item(node, "table")["comment"] = marker;
        Reject(node.ToJsonString(), "observation.identity");
    }

    /// <summary>Handles remain exact positive integers; numeric-looking strings and zero are not identities.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Observation_NonpositiveHandlesReject(int handle)
    {
        foreach (var kind in new[] { "table", "chain" })
        {
            var node = JsonNode.Parse(Json)!;
            Item(node, kind)["handle"] = handle;
            Reject(node.ToJsonString(), "observation.handle");
        }
    }

    /// <summary>Unknown schemas, priorities, missing identities and handle types fail with stable diagnostics.</summary>
    [Fact]
    public void Observation_RejectsUnknownSchemaAndAmbiguousFields()
    {
        var node = JsonNode.Parse(Json)!;
        Item(node, "metainfo")["json_schema_version"] = 2;
        Reject(node.ToJsonString(), "observation.schema");
        node = JsonNode.Parse(Json)!;
        Item(node, "chain")["prio"] = -1;
        Reject(node.ToJsonString(), "observation.scope");
        node = JsonNode.Parse(Json)!;
        Item(node, "table").Remove("comment");
        Reject(node.ToJsonString(), "observation.fields");
        node = JsonNode.Parse(Json)!;
        Item(node, "table")["handle"] = "7";
        Reject(node.ToJsonString(), "observation.handle");
        Reject(Json.Replace("\"handle\":7", "\"handle\":7,\"handle\":8", StringComparison.Ordinal), "observation.duplicateProperty");
    }

    /// <summary>Malformed, oversized and deeply nested input never returns a partial observation.</summary>
    [Theory]
    [InlineData("")]
    [InlineData("{")]
    [InlineData("{/*comment*/\"nftables\":[]}")]
    [InlineData("{\"nftables\":[],}")]
    public void Observation_InvalidJsonRejects(string text) => Reject(text, "observation.invalidJson");

    /// <summary>Resource limits apply before expensive parsing, and malformed Unicode is not normalized.</summary>
    [Fact]
    public void Observation_BoundsDepthSizeAndUtf8()
    {
        Reject(new string(' ', 65537), "observation.tooLarge");
        Reject(new string('[', 40) + new string(']', 40), "observation.invalidJson");
        Reject("\ud800", "observation.invalidJson");
    }

    /// <summary>A copied comment on a recreated table cannot satisfy the original native handle receipt.</summary>
    [Fact]
    public void Verifier_RecreatedSameMarkerTableIsNotAdopted()
    {
        var prior = Observe();
        var node = JsonNode.Parse(Json)!;
        Item(node, "table")["handle"] = 10;
        var replacement = NftTableObservation.Parse(node.ToJsonString()).Observation!;
        var result = NftReceiptVerifier.Verify(Receipt(prior), replacement, Boot, 42);
        Assert.False(result.IsMatch);
        Assert.Equal(["handle.mismatch", "state.drift"], result.ErrorCodes);
        Assert.Throws<NotSupportedException>(() => ((IList<string>)result.ErrorCodes).Clear());
    }

    /// <summary>All context/identity/state differences are retained in deterministic order.</summary>
    [Fact]
    public void Verifier_DenialsAreStableAndComplete()
    {
        var expected = Receipt(Observe());
        var node = JsonNode.Parse(Json)!;
        Item(node, "table")["comment"] = new NftTableIdentity(Other, Resource).Comment;
        Item(node, "table")["handle"] = 8;
        Item(node, "chain")["policy"] = "drop";
        var actual = NftTableObservation.Parse(node.ToJsonString()).Observation!;
        Assert.Equal(["context.bootChanged", "context.namespaceChanged", "identity.mismatch", "handle.mismatch", "state.drift"],
            NftReceiptVerifier.Verify(expected, actual, Other, 43).ErrorCodes);
        Assert.Contains("context.invalid", NftReceiptVerifier.Verify(expected, actual, Guid.Empty, 0).ErrorCodes);
    }

    /// <summary>Policy and chain-handle drift are detected even when the table marker and handle are unchanged.</summary>
    [Theory]
    [InlineData("policy")]
    [InlineData("handle")]
    public void Verifier_ChainDriftRejects(string field)
    {
        var node = JsonNode.Parse(Json)!;
        Item(node, "chain")[field] = field == "policy" ? JsonValue.Create("drop") : JsonValue.Create(10);
        var actual = NftTableObservation.Parse(node.ToJsonString()).Observation!;
        Assert.Equal(["state.drift"], NftReceiptVerifier.Verify(Receipt(Observe()), actual, Boot, 42).ErrorCodes);
    }

    private static JsonObject Item(JsonNode root, string kind)
        => root["nftables"]!.AsArray().Select(value => value!.AsObject()).Single(value => value.ContainsKey(kind))[kind]!.AsObject();
    private static NftTableObservation Observe() => NftTableObservation.Parse(Json).Observation!;
    private static NftTableReceipt Receipt(NftTableObservation actual) => new(Boot, 42, actual.Identity, actual.TableHandle, actual.StateDigest);
    private static void Reject(string json, string code)
    {
        var result = NftTableObservation.Parse(json);
        Assert.False(result.IsSuccess);
        Assert.Null(result.Observation);
        Assert.Equal(code, result.ErrorCode);
    }
}

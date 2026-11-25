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

    private static JsonNode CreationEcho()
    {
        var objects = JsonNode.Parse(Json)!["nftables"]!.AsArray();
        return new JsonObject
        {
            ["nftables"] = new JsonArray(new JsonObject { ["create"] = objects[1]!.DeepClone() },
                new JsonObject { ["add"] = objects[2]!.DeepClone() })
        };
    }

    /// <summary>The echoed transaction binds the actual handles independently of a subsequent listing.</summary>
    [Fact]
    public void EnrollmentEcho_RequiresExactCreateAndAcceptBaseline()
    {
        var echo = CreationEcho();
        var parsed = NftTableObservation.ParseEnrollmentEcho(echo.ToJsonString()).Observation!;
        Assert.Equal(Observe().StateDigest, parsed.StateDigest);
        Assert.False(NftTableObservation.ParseEnrollmentEcho(Json).IsSuccess);
        Assert.False(NftTableObservation.Parse(echo.ToJsonString()).IsSuccess);
        var chain = echo["nftables"]![1]!["add"]!["chain"]!;
        chain["handle"] = 99;
        Assert.NotEqual(Observe().StateDigest, NftTableObservation.ParseEnrollmentEcho(echo.ToJsonString()).Observation!.StateDigest);
        chain["policy"] = "drop";
        Assert.False(NftTableObservation.ParseEnrollmentEcho(echo.ToJsonString()).IsSuccess);
    }

    /// <summary>An add, missing handle, additional operation or duplicate key cannot prove exclusive creation.</summary>
    [Theory]
    [InlineData("create", "add")]
    [InlineData("handle", "unknown")]
    [InlineData("\"create\":", "\"create\":{},\"create\":")]
    [InlineData("]}", ",{}]}")]
    public void EnrollmentEcho_RejectsAmbiguousOperations(string before, string after)
    {
        Assert.False(NftTableObservation.ParseEnrollmentEcho(CreationEcho().ToJsonString().Replace(before, after)).IsSuccess);
    }

    /// <summary>Atomic replacement echo supports drop chains and schema-1 add-rule objects while rejecting non-replacement shapes.</summary>
    [Fact]
    public void ReplacementEcho_AcceptsRuleBearingEchoAndRejectsInvalidOperations()
    {
        var echo = CreationEcho();
        echo["nftables"]![1]!["add"]!["chain"]!["policy"] = "drop";
        echo["nftables"]!.AsArray().Add(new JsonObject
        {
            ["add"] = new JsonObject
            {
                ["rule"] = JsonNode.Parse("""{"family":"inet","table":"nergal_filter","chain":"input","handle":14,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.0.2.0","len":24}}}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"accept":null}]}""")
            }
        });

        var parsed = NftTableObservation.ParseReplacementEcho(echo.ToJsonString());
        Assert.True(parsed.IsSuccess, parsed.ErrorCode);
        var observation = parsed.Observation!;
        Assert.Equal(FilterVerdict.Drop, observation.DefaultVerdict);
        var expectedRule = Assert.Single(observation.Policy.Rules)!;
        Assert.Equal(IpFamily.IPv4, expectedRule.Family);
        Assert.Equal("192.0.2.0/24", expectedRule.Source!.Value);
        Assert.Equal(443, expectedRule.DestinationPort);

        var bad = echo.DeepClone()!;
        bad["nftables"]!.AsArray()[2] = new JsonObject { ["delete"] = new JsonObject { ["table"] = new JsonObject() } };
        var badResult = NftTableObservation.ParseReplacementEcho(bad.ToJsonString());
        Assert.False(badResult.IsSuccess);
        Assert.Equal("observation.replacementEcho", badResult.ErrorCode);
        Assert.False(NftTableObservation.ParseReplacementEcho(Json).IsSuccess);
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

    /// <summary>Complete schema-1 rules round-trip through compilation, native JSON observation, and handle/order-bound digests.</summary>
    [Fact]
    public void Schema1Rules_ReconstructPolicyAndBindDigest()
    {
        var identity = new NftTableIdentity(Owner, Resource);
        var policy = new FilterPolicy(1, FilterVerdict.Drop,
        [
            new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Accept, new("0.0.0.0/0")),
            new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, new("192.0.2.1/32"), new("198.51.100.0/24"), 443),
            new(IpFamily.IPv4, FilterProtocol.Udp, FilterVerdict.Drop, DestinationPort: 53),
            new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept),
            new(IpFamily.IPv4, FilterProtocol.Icmp, FilterVerdict.Accept, new("192.0.2.0/24")),
            new(IpFamily.IPv6, FilterProtocol.Udp, FilterVerdict.Accept, new("2001:db8::1/128"), new("::/0"), 5353),
            new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept),
        ]);
        var compiled = NftFilterCompiler.Compile(policy, identity);
        Assert.True(compiled.IsSuccess);

        var node = JsonNode.Parse(Json)!;
        Item(node, "chain")["policy"] = "drop";
        var items = node["nftables"]!.AsArray();
        string[] rulesJson =
        [
            """{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":10,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"0.0.0.0","len":0}}}},{"accept":null}]}}""",
            """{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":11,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"192.0.2.1"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":{"prefix":{"addr":"198.51.100.0","len":24}}}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"accept":null}]}}""",
            """{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":12,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":53}},{"drop":null}]}}""",
            """{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":13,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"accept":null}]}}""",
            """{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":14,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.0.2.0","len":24}}}},{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"icmp"}},{"accept":null}]}}""",
            """{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":15,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":"2001:db8::1"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"daddr"}},"right":{"prefix":{"addr":"::","len":0}}}},{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":5353}},{"accept":null}]}}""",
            """{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":16,"expr":[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"ipv6-icmp"}},{"accept":null}]}}""",
        ];
        foreach (var entry in rulesJson)
        {
            items.Add(JsonNode.Parse(entry)!);
        }

        var parsed = NftTableObservation.Parse(node.ToJsonString());
        Assert.True(parsed.IsSuccess, parsed.ErrorCode);
        var observation = parsed.Observation!;
        Assert.Equal(compiled.Candidate, NftFilterCompiler.Compile(observation.Policy, observation.Identity).Candidate);

        var originalDigest = observation.StateDigest;
        items[4]!["rule"]!["expr"]![2]!["match"]!["right"] = 8443;
        var changed = NftTableObservation.Parse(node.ToJsonString()).Observation!;
        Assert.NotEqual(originalDigest, changed.StateDigest);
    }

    /// <summary>Non-canonical CIDR prefixes, redundant implicit matches, bad ports, and out-of-order match expressions fail closed.</summary>
    [Theory]
    [InlineData("""{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":10,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.0.2.1","len":24}}}},{"accept":null}]}}""")]
    [InlineData("""{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":10,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"192.0.2.1","len":32}}}},{"accept":null}]}}""")]
    [InlineData("""{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":10,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"192.0.2.0/24"}},{"accept":null}]}}""")]
    [InlineData("""{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":10,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"192.0.2.1"}},{"accept":null}]}}""")]
    [InlineData("""{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":10,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"accept":null}]}}""")]
    [InlineData("""{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":10,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"icmp"}},{"accept":null}]}}""")]
    [InlineData("""{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":10,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"192.0.2.1"}},{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"192.0.2.2"}},{"accept":null}]}}""")]
    [InlineData("""{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":10,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":0}},{"accept":null}]}}""")]
    [InlineData("""{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":10,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":65536}},{"accept":null}]}}""")]
    public void Schema1Rules_RejectNonCanonicalAndAmbiguousExpressions(string ruleJson)
    {
        var node = JsonNode.Parse(Json)!;
        node["nftables"]!.AsArray().Add(JsonNode.Parse(ruleJson)!);
        Reject(node.ToJsonString(), "observation.rule");
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

    /// <summary>Schema-2 three-chain tables reconstruct stateful, interface, and ICMPv6 policies in full round-trip.</summary>
    [Fact]
    public void Schema2_ObservationAndReplacementEcho_RoundTripsAndDetectsDrift()
    {
        var identity = new NftTableIdentity(Owner, Resource);
        var policy = new FilterPolicy(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Accept,
        [
            new(IpFamily.IPv6, FilterProtocol.IcmpV6, FilterVerdict.Accept,
                Chain: FilterChainKind.Input, InputInterface: "eth0", IcmpType: FilterIcmpTypes.NdNeighborSolicit),
            new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept,
                DestinationPort: 443, Chain: FilterChainKind.Forward, InputInterface: "eth0", OutputInterface: "eth1",
                ConnectionStates: ConnectionStateFlags.New),
            new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Accept,
                Chain: FilterChainKind.Forward, InputInterface: "eth1", OutputInterface: "eth0",
                ConnectionStates: ConnectionStateFlags.Established | ConnectionStateFlags.Related),
            new(IpFamily.IPv6, FilterProtocol.Any, FilterVerdict.Drop,
                Chain: FilterChainKind.Output, OutputInterface: "eth1", ConnectionStates: ConnectionStateFlags.Invalid),
        ]);
        var compiled = NftFilterCompiler.Compile(policy, identity);
        Assert.True(compiled.IsSuccess);

        var listing = Schema2Listing();
        var parsed = NftTableObservation.Parse(listing.ToJsonString());
        Assert.True(parsed.IsSuccess, parsed.ErrorCode);
        var observation = parsed.Observation!;
        Assert.Equal(2, observation.Policy.SchemaVersion);
        Assert.Equal(11UL, observation.ForwardChainHandle);
        Assert.Equal(12UL, observation.OutputChainHandle);
        Assert.Equal(compiled.Candidate, NftFilterCompiler.Compile(observation.Policy, observation.Identity).Candidate);

        var echo = Schema2ReplacementEcho();
        var echoed = NftTableObservation.ParseReplacementEcho(echo.ToJsonString());
        Assert.True(echoed.IsSuccess, echoed.ErrorCode);
        Assert.Equal(observation.StateDigest, echoed.Observation!.StateDigest);

        listing["nftables"]![3]!["chain"]!["policy"] = "accept";
        var drifted = NftTableObservation.Parse(listing.ToJsonString()).Observation!;
        Assert.NotEqual(observation.StateDigest, drifted.StateDigest);

        var ruleMutated = Schema2Listing();
        ruleMutated["nftables"]![6]!["rule"]!["expr"]![3]!["match"]!["right"] = "established";
        Assert.NotEqual(observation.StateDigest, NftTableObservation.Parse(ruleMutated.ToJsonString()).Observation!.StateDigest);
    }

    /// <summary>Schema-2 observations fail closed on incomplete chains, out-of-order rules, bad conntrack order, or wrong interface directions.</summary>
    [Fact]
    public void Schema2_RejectsIncompleteChainsAndUnsupportedMatchers()
    {
        var twoChains = Schema2Listing();
        twoChains["nftables"]!.AsArray().RemoveAt(4);
        Reject(twoChains.ToJsonString(), "observation.unsupportedObjects");

        var wrongStateOrder = Schema2Listing();
        wrongStateOrder["nftables"]![7]!["rule"]!["expr"]![2]!["match"]!["right"] = JsonNode.Parse("""["related","established"]""")!;
        Reject(wrongStateOrder.ToJsonString(), "observation.rule");

        var wrongIifOnOutput = Schema2Listing();
        wrongIifOnOutput["nftables"]![8]!["rule"]!["expr"]![1] = JsonNode.Parse("""{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}}""")!;
        Reject(wrongIifOnOutput.ToJsonString(), "observation.rule");

        var outOfChainOrder = Schema2Listing();
        var array = outOfChainOrder["nftables"]!.AsArray();
        var fwdRule = array[6]!.DeepClone();
        array.RemoveAt(6);
        array.Add(fwdRule);
        Reject(outOfChainOrder.ToJsonString(), "observation.scope");
    }

    /// <summary>Schema-2 per-source rate-limit observations tolerate runtime set elements while binding handles, rates, and families.</summary>
    [Fact]
    public void Schema2_RateLimitObservation_RoundTripsAndDetectsConfigDrift()
    {
        var identity = new NftTableIdentity(Owner, Resource);
        var policy = new FilterPolicy(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop,
        [
            new(IpFamily.IPv4, FilterProtocol.Udp, FilterVerdict.Accept, DestinationPort: 18445,
                RateLimit: new(2, RateLimitTimeUnit.Minute, 2, 60)),
            new(IpFamily.IPv6, FilterProtocol.Tcp, FilterVerdict.Accept, DestinationPort: 22,
                Chain: FilterChainKind.Forward, RateLimit: new(10, RateLimitTimeUnit.Second, 5, 30)),
        ]);
        var compiled = NftFilterCompiler.Compile(policy, identity);
        Assert.True(compiled.IsSuccess);

        var listing = Schema2RateLimitListing(includeRuntimeElems: false);
        var parsedClean = NftTableObservation.Parse(listing.ToJsonString());
        Assert.True(parsedClean.IsSuccess, parsedClean.ErrorCode);
        Assert.Equal(compiled.Candidate, NftFilterCompiler.Compile(parsedClean.Observation!.Policy, identity).Candidate);

        var liveWithElems = Schema2RateLimitListing(includeRuntimeElems: true);
        var parsedLive = NftTableObservation.Parse(liveWithElems.ToJsonString());
        Assert.True(parsedLive.IsSuccess, parsedLive.ErrorCode);
        Assert.Equal(parsedClean.Observation.StateDigest, parsedLive.Observation!.StateDigest);

        var echoed = NftTableObservation.ParseReplacementEcho(Schema2RateLimitReplacementEcho().ToJsonString());
        Assert.True(echoed.IsSuccess, echoed.ErrorCode);
        Assert.Equal(parsedClean.Observation.StateDigest, echoed.Observation!.StateDigest);

        // Enforcement changes must change StateDigest, and unreferenced/misnamed sets fail closed.
        liveWithElems["nftables"]![7]!["rule"]!["expr"]![1]!["set"]!["stmt"]![0]!["limit"]!["burst"] = 3;
        Assert.NotEqual(parsedClean.Observation.StateDigest, NftTableObservation.Parse(liveWithElems.ToJsonString()).Observation!.StateDigest);

        var badName = Schema2RateLimitListing(includeRuntimeElems: false);
        badName["nftables"]![5]!["set"]!["name"] = "foreign_set";
        Reject(badName.ToJsonString(), "observation.scope");

        var echoWithCount = Schema2RateLimitReplacementEcho();
        echoWithCount["nftables"]![4]!["add"]!["set"]!["count"] = 1;
        Assert.False(NftTableObservation.ParseReplacementEcho(echoWithCount.ToJsonString()).IsSuccess);

        var unreferenced = Schema2RateLimitListing(includeRuntimeElems: false);
        unreferenced["nftables"]!.AsArray().RemoveAt(8);
        Reject(unreferenced.ToJsonString(), "observation.unsupportedObjects");
    }

    /// <summary>Schema-2 ct status dnat rules reconstruct MatchOriginalDestinationDnat and detect status drift.</summary>
    [Fact]
    public void Schema2_CtStatusDnat_RoundTripsAndDetectsDrift()
    {
        var identity = new NftTableIdentity(Owner, Resource);
        var policy = new FilterPolicy(2, FilterVerdict.Drop, FilterVerdict.Drop, FilterVerdict.Drop,
        [
            new(IpFamily.IPv4, FilterProtocol.Tcp, FilterVerdict.Accept, DestinationPort: 18447,
                Chain: FilterChainKind.Forward, InputInterface: "r_cli", OutputInterface: "r_srv",
                ConnectionStates: ConnectionStateFlags.New, MatchOriginalDestinationDnat: true),
        ]);
        var compiled = NftFilterCompiler.Compile(policy, identity);
        Assert.True(compiled.IsSuccess);

        var listing = JsonNode.Parse("""
            {"nftables":[
              {"metainfo":{"version":"1.1.7","release_name":"fixture","json_schema_version":1}},
              {"table":{"family":"inet","name":"nergal_filter","handle":7,"comment":"MARKER"}},
              {"chain":{"family":"inet","table":"nergal_filter","name":"input","handle":9,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
              {"chain":{"family":"inet","table":"nergal_filter","name":"forward","handle":11,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
              {"chain":{"family":"inet","table":"nergal_filter","name":"output","handle":12,"type":"filter","hook":"output","prio":0,"policy":"drop"}},
              {"rule":{"family":"inet","table":"nergal_filter","chain":"forward","handle":21,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"r_cli"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"r_srv"}},{"match":{"op":"in","left":{"ct":{"key":"status"}},"right":"dnat"}},{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"new"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":18447}},{"accept":null}]}}
            ]}
            """.Replace("MARKER", identity.Comment, StringComparison.Ordinal))!;

        var parsed = NftTableObservation.Parse(listing.ToJsonString());
        Assert.True(parsed.IsSuccess, parsed.ErrorCode);
        Assert.Equal(compiled.Candidate, NftFilterCompiler.Compile(parsed.Observation!.Policy, identity).Candidate);

        var withoutDnat = JsonNode.Parse(listing.ToJsonString())!;
        withoutDnat["nftables"]![5]!["rule"]!["expr"]!.AsArray().RemoveAt(3);
        var drifted = NftTableObservation.Parse(withoutDnat.ToJsonString());
        Assert.True(drifted.IsSuccess, drifted.ErrorCode);
        Assert.NotEqual(parsed.Observation.StateDigest, drifted.Observation!.StateDigest);

        var wrongOrder = JsonNode.Parse(listing.ToJsonString())!;
        var expr = wrongOrder["nftables"]![5]!["rule"]!["expr"]!.AsArray();
        var dnatExpr = expr[3]!.DeepClone();
        expr.RemoveAt(3);
        expr.Insert(4, dnatExpr);
        Reject(wrongOrder.ToJsonString(), "observation.rule");
    }

    /// <summary>Changing only dynamic-set add/update is observable drift, not a harmless syntax variation.</summary>
    [Fact]
    public void MeterRefresh_ObservationBindsOperationAndRejectsUnknownOperations()
    {
        var original = Schema2RateLimitListing(false);
        var before = NftTableObservation.Parse(original.ToJsonString());
        foreach (var entry in original["nftables"]!.AsArray())
        {
            if (entry?["rule"]?["expr"] is not JsonArray expressions) { continue; }
            foreach (var expression in expressions)
            { if (expression?["set"] is JsonObject set) { set["op"] = "update"; } }
        }
        var after = NftTableObservation.Parse(original.ToJsonString());
        Assert.True(before.IsSuccess); Assert.True(after.IsSuccess);
        Assert.NotEqual(before.Observation!.StateDigest, after.Observation!.StateDigest);
        Assert.All(after.Observation.Policy.Rules, r => Assert.True(r!.RateLimit!.RefreshEntryTimeout));
        Assert.Contains("update @", NftFilterCompiler.Compile(after.Observation.Policy, after.Observation.Identity).Candidate!);
        Assert.False(NftTableObservation.Parse(original.ToJsonString().Replace("\"update\"", "\"delete\"", StringComparison.Ordinal)).IsSuccess);
    }

    private static JsonNode Schema2RateLimitListing(bool includeRuntimeElems)
    {
        var set0 = includeRuntimeElems
            ? """{"set":{"family":"inet","name":"nergal_rl_0","table":"nergal_filter","type":"ipv4_addr","handle":15,"size":65535,"count":1,"flags":["timeout","dynamic"],"elem":[{"elem":{"val":"192.0.2.2","timeout":60,"expires":59,"limit":{"rate":2,"burst":2,"per":"minute"}}}]}}"""
            : """{"set":{"family":"inet","name":"nergal_rl_0","table":"nergal_filter","type":"ipv4_addr","handle":15,"size":65535,"flags":["timeout","dynamic"]}}""";
        return JsonNode.Parse("""
            {"nftables":[
              {"metainfo":{"version":"1.1.7","release_name":"fixture","json_schema_version":1}},
              {"table":{"family":"inet","name":"nergal_filter","handle":7,"comment":"MARKER"}},
              {"chain":{"family":"inet","table":"nergal_filter","name":"input","handle":9,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
              {"chain":{"family":"inet","table":"nergal_filter","name":"forward","handle":11,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
              {"chain":{"family":"inet","table":"nergal_filter","name":"output","handle":12,"type":"filter","hook":"output","prio":0,"policy":"drop"}},
              SET0,
              {"set":{"family":"inet","name":"nergal_rl_1","table":"nergal_filter","type":"ipv6_addr","handle":16,"size":65535,"flags":["timeout","dynamic"]}},
              {"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":20,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":18445}},{"set":{"op":"add","elem":{"elem":{"val":{"payload":{"protocol":"ip","field":"saddr"}},"timeout":60}},"set":"@nergal_rl_0","stmt":[{"limit":{"rate":2,"burst":2,"per":"minute"}}]}},{"accept":null}]}},
              {"rule":{"family":"inet","table":"nergal_filter","chain":"forward","handle":21,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},{"set":{"op":"add","elem":{"elem":{"val":{"payload":{"protocol":"ip6","field":"saddr"}},"timeout":30}},"set":"@nergal_rl_1","stmt":[{"limit":{"rate":10,"burst":5,"per":"second"}}]}},{"accept":null}]}}
            ]}
            """
            .Replace("SET0", set0, StringComparison.Ordinal)
            .Replace("MARKER", new NftTableIdentity(Owner, Resource).Comment, StringComparison.Ordinal))!;
    }

    private static JsonNode Schema2RateLimitReplacementEcho() => JsonNode.Parse("""
        {"nftables":[
          {"create":{"table":{"family":"inet","name":"nergal_filter","handle":7,"comment":"MARKER"}}},
          {"add":{"chain":{"family":"inet","table":"nergal_filter","name":"input","handle":9,"type":"filter","hook":"input","prio":0,"policy":"drop"}}},
          {"add":{"chain":{"family":"inet","table":"nergal_filter","name":"forward","handle":11,"type":"filter","hook":"forward","prio":0,"policy":"drop"}}},
          {"add":{"chain":{"family":"inet","table":"nergal_filter","name":"output","handle":12,"type":"filter","hook":"output","prio":0,"policy":"drop"}}},
          {"add":{"set":{"family":"inet","name":"nergal_rl_0","table":"nergal_filter","type":"ipv4_addr","handle":15,"size":65535,"flags":["timeout","dynamic"]}}},
          {"add":{"set":{"family":"inet","name":"nergal_rl_1","table":"nergal_filter","type":"ipv6_addr","handle":16,"size":65535,"flags":["timeout","dynamic"]}}},
          {"add":{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":20,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":18445}},{"set":{"op":"add","elem":{"elem":{"val":{"payload":{"protocol":"ip","field":"saddr"}},"timeout":60}},"set":"@nergal_rl_0","stmt":[{"limit":{"rate":2,"burst":2,"per":"minute"}}]}},{"accept":null}]}}},
          {"add":{"rule":{"family":"inet","table":"nergal_filter","chain":"forward","handle":21,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":22}},{"set":{"op":"add","elem":{"elem":{"val":{"payload":{"protocol":"ip6","field":"saddr"}},"timeout":30}},"set":"@nergal_rl_1","stmt":[{"limit":{"rate":10,"burst":5,"per":"second"}}]}},{"accept":null}]}}}
        ]}
        """.Replace("MARKER", new NftTableIdentity(Owner, Resource).Comment, StringComparison.Ordinal))!;

    private static JsonNode Schema2Listing() => JsonNode.Parse("""
        {"nftables":[
          {"metainfo":{"version":"1.1.7","release_name":"fixture","json_schema_version":1}},
          {"table":{"family":"inet","name":"nergal_filter","handle":7,"comment":"MARKER"}},
          {"chain":{"family":"inet","table":"nergal_filter","name":"input","handle":9,"type":"filter","hook":"input","prio":0,"policy":"drop"}},
          {"chain":{"family":"inet","table":"nergal_filter","name":"forward","handle":11,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
          {"chain":{"family":"inet","table":"nergal_filter","name":"output","handle":12,"type":"filter","hook":"output","prio":0,"policy":"accept"}},
          {"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":20,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},{"match":{"op":"==","left":{"payload":{"protocol":"icmpv6","field":"type"}},"right":"nd-neighbor-solicit"}},{"accept":null}]}},
          {"rule":{"family":"inet","table":"nergal_filter","chain":"forward","handle":21,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth1"}},{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"new"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"accept":null}]}},
          {"rule":{"family":"inet","table":"nergal_filter","chain":"forward","handle":22,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth1"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth0"}},{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},{"accept":null}]}},
          {"rule":{"family":"inet","table":"nergal_filter","chain":"output","handle":23,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv6"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth1"}},{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"invalid"}},{"drop":null}]}}
        ]}
        """.Replace("MARKER", new NftTableIdentity(Owner, Resource).Comment, StringComparison.Ordinal))!;

    private static JsonNode Schema2ReplacementEcho() => JsonNode.Parse("""
        {"nftables":[
          {"create":{"table":{"family":"inet","name":"nergal_filter","handle":7,"comment":"MARKER"}}},
          {"add":{"chain":{"family":"inet","table":"nergal_filter","name":"input","handle":9,"type":"filter","hook":"input","prio":0,"policy":"drop"}}},
          {"add":{"chain":{"family":"inet","table":"nergal_filter","name":"forward","handle":11,"type":"filter","hook":"forward","prio":0,"policy":"drop"}}},
          {"add":{"chain":{"family":"inet","table":"nergal_filter","name":"output","handle":12,"type":"filter","hook":"output","prio":0,"policy":"accept"}}},
          {"add":{"rule":{"family":"inet","table":"nergal_filter","chain":"input","handle":20,"expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},{"match":{"op":"==","left":{"payload":{"protocol":"icmpv6","field":"type"}},"right":"nd-neighbor-solicit"}},{"accept":null}]}}},
          {"add":{"rule":{"family":"inet","table":"nergal_filter","chain":"forward","handle":21,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth1"}},{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"new"}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"accept":null}]}}},
          {"add":{"rule":{"family":"inet","table":"nergal_filter","chain":"forward","handle":22,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv4"}},{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth1"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth0"}},{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},{"accept":null}]}}},
          {"add":{"rule":{"family":"inet","table":"nergal_filter","chain":"output","handle":23,"expr":[{"match":{"op":"==","left":{"meta":{"key":"nfproto"}},"right":"ipv6"}},{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"eth1"}},{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":"invalid"}},{"drop":null}]}}}
        ]}
        """.Replace("MARKER", new NftTableIdentity(Owner, Resource).Comment, StringComparison.Ordinal))!;

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

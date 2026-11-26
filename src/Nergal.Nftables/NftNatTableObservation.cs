using System.Globalization;
using System.Text.Json.Nodes;
using System.Text;
using System.Text.Json;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Result of parsing native JSON for the reserved <c>inet nergal_nat</c> table.</summary>
public sealed class NftNatObservationResult
{
    internal NftNatObservationResult(NftNatTableObservation? observation, string? errorCode)
    {
        Observation = observation;
        ErrorCode = errorCode;
    }

    /// <summary>Gets the complete NAT table observation, or null on any validation failure.</summary>
    public NftNatTableObservation? Observation { get; }

    /// <summary>Gets the stable denial code, or null on success.</summary>
    public string? ErrorCode { get; }

    /// <summary>Gets whether the native NAT JSON was fully recognized and valid.</summary>
    public bool IsSuccess => Observation is not null;
}

/// <summary>Immutable native observation of <c>inet nergal_nat</c> chains and ordered DNAT/SNAT rules.</summary>
public sealed class NftNatTableObservation
{
    private NftNatTableObservation(
        NftTableIdentity identity,
        ulong tableHandle,
        ulong preroutingChainHandle,
        ulong? outputChainHandle,
        ulong postroutingChainHandle,
        NatPolicy policy,
        List<(ulong Handle, DnatRule Rule)> dnatRules,
        List<(ulong Handle, SnatRule Rule)> snatRules, NftStaticSetSnapshot? named = null)
    {
        Identity = identity;
        TableHandle = tableHandle;
        PreroutingChainHandle = preroutingChainHandle;
        OutputChainHandle = outputChainHandle;
        PostroutingChainHandle = postroutingChainHandle;
        Policy = policy;

        var completeSets = dnatRules.Any(e => e.Rule.OriginalPorts is not null || e.Rule.SourcePrefixes is not null || e.Rule.DestinationPrefixes is not null) || snatRules.Any(e => e.Rule.SourcePrefixes is not null || e.Rule.DestinationPrefixes is not null);
        var originalTuple = snatRules.Any(e => e.Rule.MatchOriginalDestinationDnat);
        var extended = originalTuple || outputChainHandle.HasValue || completeSets || dnatRules.Any(e => e.Rule.NegateSource || e.Rule.NegateDestination || e.Rule.NegateInputInterface || e.Rule.InputInterfaceSelector is not null) ||
            snatRules.Any(e => e.Rule.Action != NatPostroutingAction.Snat || e.Rule.NegateSource || e.Rule.NegateDestination ||
                e.Rule.NegateInputInterface || e.Rule.NegateOutputInterface || e.Rule.InputInterface is not null || e.Rule.Protocol != FilterProtocol.Any ||
                e.Rule.InputInterfaceSelector is not null || e.Rule.OutputInterfaceSelector is not null);
        var projection = new StringBuilder(string.Join('\n',
            originalTuple ? "nergal-nat-observation-v5" : outputChainHandle.HasValue ? "nergal-nat-observation-v4" : completeSets ? "nergal-nat-observation-v3" : extended ? "nergal-nat-observation-v2" : "nergal-nat-observation-v1",
            identity.Comment,
            tableHandle.ToString(CultureInfo.InvariantCulture),
            string.Join(' ', preroutingChainHandle.ToString(CultureInfo.InvariantCulture), "inet", NftNatCompiler.TableName, "prerouting", "nat", "prerouting", "-100", "accept"),
            string.Join(' ', postroutingChainHandle.ToString(CultureInfo.InvariantCulture), "inet", NftNatCompiler.TableName, "postrouting", "nat", "postrouting", "100", "accept")));
        if (outputChainHandle is { } outputHandle)
        {
            projection.Append('\n').Append(outputHandle.ToString(CultureInfo.InvariantCulture))
                .Append(" inet " + NftNatCompiler.TableName + " output nat output -100 accept");
        }

        foreach (var (handle, rule) in dnatRules)
        {
            projection.Append('\n')
                .Append(handle.ToString(CultureInfo.InvariantCulture)).Append(" dnat ")
                .Append(rule.Family == IpFamily.IPv4 ? "ipv4 " : "ipv6 ")
                .Append(rule.InputInterface ?? "-").Append(' ')
                .Append(rule.Source?.Value ?? "-").Append(' ')
                .Append(rule.OriginalDestination?.Value ?? "-").Append(' ')
                .Append(rule.Protocol).Append(' ')
                .Append(rule.OriginalPort?.ToString(CultureInfo.InvariantCulture) ?? "-").Append(' ')
                .Append(rule.CountPackets ? "counter " : "")
                .Append(rule.TranslatedAddress).Append(' ')
                .Append(rule.TranslatedPort?.ToString(CultureInfo.InvariantCulture) ?? "-");
        }

        foreach (var (handle, rule) in snatRules)
        {
            projection.Append('\n')
                .Append(handle.ToString(CultureInfo.InvariantCulture)).Append(" snat ")
                .Append(rule.Family == IpFamily.IPv4 ? "ipv4 " : "ipv6 ")
                .Append(rule.OutputInterface ?? "-").Append(' ')
                .Append(rule.Source?.Value ?? "-").Append(' ')
                .Append(rule.Destination?.Value ?? "-").Append(' ')
                .Append(rule.CountPackets ? "counter " : "")
                .Append(rule.TranslatedAddress);
        }

        if (extended)
        {
            // Canonical typed semantics include every extended matcher/action.
            projection.Append('\n').Append(PolicyBundleJsonCodec.EncodeBundle(new(1,
                new FilterPolicy(1, FilterVerdict.Drop, []), policy), indented: false));
        }
        StateDigest = CandidateDigest.FromText(projection.ToString());
        if (named is { IsEmpty: false })
        {
            Policy = new(policy.SchemaVersion, dnatRules.Select(r => named.Restore(r.Handle, r.Rule)), snatRules.Select(r => named.Restore(r.Handle, r.Rule)));
            StateDigest = named.Bind(StateDigest);
        }
    }

    /// <summary>Gets the canonical owner/resource marker parsed from the table comment.</summary>
    public NftTableIdentity Identity { get; }

    /// <summary>Gets the positive native table handle.</summary>
    public ulong TableHandle { get; }

    /// <summary>Gets the positive native prerouting chain handle.</summary>
    public ulong PreroutingChainHandle { get; }

    /// <summary>Gets the native OUTPUT chain handle when active OUTPUT DNAT rules are present.</summary>
    public ulong? OutputChainHandle { get; }

    /// <summary>Gets the positive native postrouting chain handle.</summary>
    public ulong PostroutingChainHandle { get; }

    /// <summary>Gets the reconstructed typed NAT policy.</summary>
    public NatPolicy Policy { get; }

    /// <summary>Gets the SHA-256 fingerprint over all recognized NAT objects, handles, and translations.</summary>
    public CandidateDigest StateDigest { get; }

    /// <summary>Parses a full native <c>nft --json list table inet nergal_nat</c> snapshot.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="json"/> is null.</exception>
    public static NftNatObservationResult Parse(string json) => ParseNative(json, isEcho: false);

    /// <summary>Parses handle-bearing <c>nft --echo --handle --json</c> output for <c>inet nergal_nat</c>.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="json"/> is null.</exception>
    public static NftNatObservationResult ParseReplacementEcho(string json) => ParseNative(json, isEcho: true);

    private static NftNatObservationResult ParseNative(string json, bool isEcho)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            if (new UTF8Encoding(false, true).GetByteCount(json) > 65536)
            {
                return Deny("observation.tooLarge");
            }

            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            if (NftJsonHelpers.HasDuplicateProperties(document.RootElement))
            {
                return Deny("observation.duplicateProperty");
            }

            var root = document.RootElement;
            if (!NftJsonHelpers.Properties(root, "nftables") || root.GetProperty("nftables").ValueKind != JsonValueKind.Array)
            {
                return Deny("observation.shape");
            }

            var named = NftStaticSetSnapshot.Expand(json, "inet", NftNatCompiler.TableName, isEcho);
            using var expanded = named.IsEmpty ? null : JsonDocument.Parse(named.Json);
            var items = (expanded?.RootElement ?? root).GetProperty("nftables").EnumerateArray().ToArray();
            if (!isEcho && (items.Length < 4 || !NftJsonHelpers.Properties(items[0], "metainfo")))
            {
                return Deny("observation.unsupportedObjects");
            }
            if (!isEcho && !NftJsonHelpers.TryReadMetaHeader(items))
            {
                return Deny("observation.schema");
            }

            var index = isEcho ? 0 : 1;
            var unexpectedObject = isEcho ? "observation.replacementEcho" : "observation.unsupportedObjects";
            if (!TryReadObject(items, index++, isEcho, "create", "table", out var table) ||
                !TryReadObject(items, index++, isEcho, "add", "chain", out var preChain) ||
                !TryReadObject(items, index++, isEcho, "add", "chain", out var nextChain))
            {
                return Deny(unexpectedObject);
            }
            if (!NftJsonHelpers.Properties(table, "family", "name", "handle", "comment")) { return Deny("observation.fields"); }
            if (table.GetProperty("family").GetString() != "inet" || table.GetProperty("name").GetString() != NftNatCompiler.TableName)
            {
                return Deny("observation.scope");
            }
            if (table.GetProperty("handle").ValueKind != JsonValueKind.Number || !table.GetProperty("handle").TryGetUInt64(out var tableHandle) || tableHandle == 0)
            {
                return Deny("observation.handle");
            }
            var identity = NftTableIdentity.Parse(table.GetProperty("comment").GetString() ?? "");
            if (identity is null) { return Deny("observation.identity"); }

            var handles = new HashSet<ulong>();
            var error = ReadChain(preChain, "prerouting", -100, handles, out var preHandle);
            if (error is not null) { return Deny(error); }
            ulong? outputHandle = null;
            if (nextChain.TryGetProperty("name", out var name) && name.GetString() == "output")
            {
                error = ReadChain(nextChain, "output", -100, handles, out var handle);
                if (error is not null) { return Deny(error); }
                outputHandle = handle;
                if (!TryReadObject(items, index++, isEcho, "add", "chain", out nextChain)) { return Deny(unexpectedObject); }
            }
            error = ReadChain(nextChain, "postrouting", 100, handles, out var postHandle);
            if (error is not null) { return Deny(error); }

            var dnatRules = new List<(ulong Handle, DnatRule Rule)>();
            var snatRules = new List<(ulong Handle, SnatRule Rule)>();
            var sawOutputRule = false;
            for (; index < items.Length; index++)
            {
                if (!TryReadObject(items, index, isEcho, "add", "rule", out var rule))
                {
                    return Deny(unexpectedObject);
                }

                if (!NftJsonHelpers.Properties(rule, "family", "table", "chain", "handle", "expr"))
                {
                    return Deny("observation.unsupportedObjects");
                }

                if (rule.GetProperty("family").GetString() != "inet" || rule.GetProperty("table").GetString() != NftNatCompiler.TableName)
                {
                    return Deny("observation.scope");
                }

                var chainName = rule.GetProperty("chain").GetString();
                if (!rule.GetProperty("handle").TryGetUInt64(out var ruleHandle) || ruleHandle == 0 || !handles.Add(ruleHandle))
                {
                    return Deny("observation.handle");
                }

                if (chainName is "prerouting" or "output")
                {
                    if (snatRules.Count != 0 || (chainName == "output" ? !outputHandle.HasValue : sawOutputRule))
                    {
                        return Deny("observation.scope");
                    }

                    var parsed = ParseDnatRule(rule.GetProperty("expr"));
                    if (parsed is null) { return Deny("observation.rule"); }
                    if (chainName == "output")
                    {
                        parsed = parsed with { Hook = DnatHook.Output };
                        sawOutputRule = true;
                    }
                    dnatRules.Add((ruleHandle, parsed));
                }
                else if (chainName == "postrouting")
                {
                    var parsed = ParseSnatRule(rule.GetProperty("expr"));
                    if (parsed is null) { return Deny("observation.rule"); }
                    snatRules.Add((ruleHandle, parsed));
                }
                else
                {
                    return Deny("observation.scope");
                }
            }

            if (outputHandle.HasValue && !sawOutputRule) { return Deny("observation.scope"); }
            var policy = new NatPolicy(NatPolicy.CurrentSchemaVersion,
                dnatRules.Select(entry => entry.Rule),
                snatRules.Select(entry => entry.Rule));
            if (!NftNatCompiler.Compile(policy).IsSuccess) { return Deny("observation.rule"); }
            return new(new(identity, tableHandle, preHandle, outputHandle, postHandle, policy, dnatRules, snatRules, named), null);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or EncoderFallbackException or ArgumentException or KeyNotFoundException)
        {
            return Deny("observation.invalidJson");
        }
    }

    private static bool TryReadObject(JsonElement[] items, int index, bool isEcho, string command, string kind, out JsonElement value)
    {
        value = default;
        if (index >= items.Length) { return false; }
        var item = items[index];
        if (isEcho)
        {
            if (!NftJsonHelpers.Properties(item, command)) { return false; }
            item = item.GetProperty(command);
        }
        return NftJsonHelpers.Properties(item, kind) && item.TryGetProperty(kind, out value);
    }

    private static string? ReadChain(JsonElement chain, string name, int priority, HashSet<ulong> handles, out ulong handle)
    {
        handle = 0;
        if (!NftJsonHelpers.Properties(chain, "family", "table", "name", "handle", "type", "hook", "prio", "policy"))
        {
            return "observation.fields";
        }
        if (chain.GetProperty("family").GetString() != "inet" || chain.GetProperty("table").GetString() != NftNatCompiler.TableName ||
            chain.GetProperty("name").GetString() != name || chain.GetProperty("type").GetString() != "nat" ||
            chain.GetProperty("hook").GetString() != name || chain.GetProperty("prio").ValueKind != JsonValueKind.Number ||
            !chain.GetProperty("prio").TryGetInt32(out var actualPriority) || actualPriority != priority)
        {
            return "observation.scope";
        }
        if (chain.GetProperty("handle").ValueKind != JsonValueKind.Number ||
            !chain.GetProperty("handle").TryGetUInt64(out handle) || handle == 0 || !handles.Add(handle))
        {
            return "observation.handle";
        }
        return chain.GetProperty("policy").GetString() == "accept" ? null : "observation.policy";
    }

    private static DnatRule? ParseDnatRule(JsonElement expressions)
    {
        if (expressions.ValueKind != JsonValueKind.Array || expressions.GetArrayLength() is < 2 or > 7 ||
            !TryReadCounter(expressions, out var matchCount, out var countPackets))
        {
            return null;
        }

        var count = expressions.GetArrayLength();
        var terminal = expressions[count - 1];
        if (!NftJsonHelpers.Properties(terminal, "dnat"))
        {
            return null;
        }

        var dnat = terminal.GetProperty("dnat");
        var hasPort = NftJsonHelpers.Properties(dnat, "family", "addr", "port");
        if (!hasPort && !NftJsonHelpers.Properties(dnat, "family", "addr"))
        {
            return null;
        }

        IpFamily? targetFamily = dnat.GetProperty("family").GetString() switch
        {
            "ip" => IpFamily.IPv4,
            "ip6" => IpFamily.IPv6,
            _ => null,
        };
        if (targetFamily is null || dnat.GetProperty("addr").ValueKind != JsonValueKind.String ||
            !FilterPolicyValidation.TryParseSingleIpAddress(dnat.GetProperty("addr").GetString(), out _, out var parsedAddrFamily, out var normalizedAddr) ||
            parsedAddrFamily != targetFamily.Value)
        {
            return null;
        }

        int? translatedPort = null;
        if (hasPort)
        {
            if (dnat.GetProperty("port").ValueKind != JsonValueKind.Number ||
                !dnat.GetProperty("port").TryGetInt32(out var p) ||
                p is < 1 or > 65535)
            {
                return null;
            }

            translatedPort = p;
        }

        string? inputInterface = null;
        InterfaceNameSelector? inputSelector = null;
        NetworkPrefix? source = null;
        NetworkPrefix? originalDestination = null;
        IReadOnlyList<NetworkPrefix>? sourcePrefixes = null, destinationPrefixes = null;
        var protocol = FilterProtocol.Any;
        int? originalPort = null;
        IReadOnlyList<int>? originalPorts = null;
        var hasL4Proto = false;
        var stage = -1;
        var ni = false;
        var ns = false;
        var nd = false;

        for (var index = 0; index < matchCount; index++)
        {
            if (!NftJsonHelpers.Properties(expressions[index], "match")) { return null; }
            var match = expressions[index].GetProperty("match");
            if (!NftJsonHelpers.Properties(match, "op", "left", "right") ||
                match.GetProperty("op").ValueKind != JsonValueKind.String ||
                match.GetProperty("op").GetString() is not ("==" or "!="))
            {
                return null;
            }

            var negate = match.GetProperty("op").GetString() == "!=";
            var left = match.GetProperty("left");
            var right = match.GetProperty("right");
            if (NftJsonHelpers.Properties(left, "meta") && NftJsonHelpers.Properties(left.GetProperty("meta"), "key"))
            {
                var key = left.GetProperty("meta").GetProperty("key");
                if (key.ValueKind != JsonValueKind.String) { return null; }
                var keyName = key.GetString();
                if (keyName == "iifname")
                {
                    if (stage >= 0 || !NftInterfaceNames.TryRead(right, out inputInterface, out inputSelector)) { return null; }
                    ni = negate;
                    stage = 0;
                    continue;
                }

                if (keyName == "l4proto")
                {
                    if (negate || stage >= 3 || right.ValueKind != JsonValueKind.String) { return null; }
                    FilterProtocol? l4 = right.GetString() switch
                    {
                        "tcp" => FilterProtocol.Tcp,
                        "udp" => FilterProtocol.Udp,
                        _ => null,
                    };
                    if (l4 is null) { return null; }
                    protocol = l4.Value;
                    hasL4Proto = true;
                    stage = 3;
                    continue;
                }

                return null;
            }

            if (NftJsonHelpers.Properties(left, "payload") && NftJsonHelpers.Properties(left.GetProperty("payload"), "protocol", "field"))
            {
                var payload = left.GetProperty("payload");
                var pProto = payload.GetProperty("protocol").GetString();
                var pField = payload.GetProperty("field").GetString();
                if (pField is "saddr" or "daddr")
                {
                    var nextStage = pField == "saddr" ? 1 : 2;
                    var expectedProto = targetFamily == IpFamily.IPv4 ? "ip" : "ip6";
                    if (stage >= nextStage || pProto != expectedProto) { return null; }
                    if (NftJsonHelpers.Properties(right, "set"))
                    {
                        var prefixes = NftTableObservation.ParseNetworkPrefixSet(right.GetProperty("set"), targetFamily.Value);
                        if (prefixes is null) { return null; }
                        if (nextStage == 1) { sourcePrefixes = prefixes; } else { destinationPrefixes = prefixes; }
                    }
                    else
                    {
                        var prefix = NftJsonHelpers.ParseNetworkPrefix(right, targetFamily.Value);
                        if (prefix is null) { return null; }
                        if (nextStage == 1) { source = prefix; } else { originalDestination = prefix; }
                    }
                    if (nextStage == 1) { ns = negate; } else { nd = negate; }
                    stage = nextStage;
                    continue;
                }

                if (pField == "dport")
                {
                    if (negate || stage >= 3 || pProto is not ("tcp" or "udp")) { return null; }
                    if (right.ValueKind == JsonValueKind.Number && right.TryGetInt32(out var port) && port is >= 1 and <= 65535) { originalPort = port; }
                    else if (NftJsonHelpers.Properties(right, "set") && right.GetProperty("set").ValueKind == JsonValueKind.Array)
                    {
                        var ports = new List<int>();
                        foreach (var element in right.GetProperty("set").EnumerateArray())
                        { if (element.ValueKind != JsonValueKind.Number || !element.TryGetInt32(out port) || port is < 1 or > 65535) { return null; } ports.Add(port); }
                        if (ports.Count is < 2 or > 64 || ports.Distinct().Count() != ports.Count) { return null; }
                        originalPorts = ports.Order().ToArray();
                    }
                    else { return null; }
                    protocol = pProto == "tcp" ? FilterProtocol.Tcp : FilterProtocol.Udp;
                    stage = 4;
                    continue;
                }
            }

            return null;
        }

        if (originalDestination is null && destinationPrefixes is null)
        {
            return null;
        }

        var expectL4Proto = protocol != FilterProtocol.Any && !originalPort.HasValue && originalPorts is null;
        if (hasL4Proto != expectL4Proto || (translatedPort.HasValue && protocol is not (FilterProtocol.Tcp or FilterProtocol.Udp)))
        {
            return null;
        }

        return new(targetFamily.Value, protocol, originalDestination, normalizedAddr, originalPort, translatedPort, inputInterface, source, NegateSource: ns, NegateDestination: nd, NegateInputInterface: ni, OriginalPorts: originalPorts, SourcePrefixes: sourcePrefixes, DestinationPrefixes: destinationPrefixes, CountPackets: countPackets, InputInterfaceSelector: inputSelector);
    }

    private static SnatRule? ParseSnatRule(JsonElement expressions)
    {
        if (expressions.ValueKind != JsonValueKind.Array || expressions.GetArrayLength() is < 1 or > 12 ||
            !TryReadCounter(expressions, out var matchCount, out var countPackets)) { return null; }
        var terminal = expressions[expressions.GetArrayLength() - 1];
        var action = NatPostroutingAction.Snat;
        IpFamily? targetFamily = null;
        string? normalized = null;
        if (NftJsonHelpers.Properties(terminal, "snat"))
        {
            var snat = terminal.GetProperty("snat");
            if (!NftJsonHelpers.Properties(snat, "family", "addr")) { return null; }
            targetFamily = snat.GetProperty("family").GetString() switch { "ip" => IpFamily.IPv4, "ip6" => IpFamily.IPv6, _ => null };
            if (targetFamily is null || snat.GetProperty("addr").ValueKind != JsonValueKind.String ||
                !FilterPolicyValidation.TryParseSingleIpAddress(snat.GetProperty("addr").GetString(), out _, out var parsedFamily, out normalized) ||
                parsedFamily != targetFamily) { return null; }
        }
        else if (NftJsonHelpers.Properties(terminal, "masquerade") && terminal.GetProperty("masquerade").ValueKind == JsonValueKind.Null)
        { action = NatPostroutingAction.Masquerade; }
        else if (NftJsonHelpers.Properties(terminal, "return") && terminal.GetProperty("return").ValueKind == JsonValueKind.Null)
        { action = NatPostroutingAction.Return; }
        else { return null; }

        var nodes = new JsonArray();
        var index = 0;
        while (index < matchCount && !NftOriginalTuple.IsDnatStatus(expressions[index]))
        {
            nodes.Add(JsonNode.Parse(expressions[index].GetRawText()));
            index++;
        }
        var originalFamily = index + 1 < matchCount ? NftOriginalTuple.OriginalAddressFamily(expressions[index + 1]) : null;
        var r = ParsePacketMatchers(nodes, originalFamily);
        if (r is null || (targetFamily.HasValue && targetFamily != r.Family) || r.SourceMac is not null || r.SourceMacs is not null ||
            r.ConnectionStates != ConnectionStateFlags.None || r.MatchOriginalDestinationDnat || r.RateLimit is not null || r.IcmpType is not null) { return null; }
        var matchDnat = index < matchCount;
        IReadOnlyList<NetworkPrefix>? originalSources = null, originalDestinations = null;
        if (matchDnat)
        {
            index++;
            originalSources = NftOriginalTuple.ReadOriginalPrefixes(expressions, ref index, matchCount, r.Family, "saddr");
            originalDestinations = NftOriginalTuple.ReadOriginalPrefixes(expressions, ref index, matchCount, r.Family, "daddr");
            if (index != matchCount) { return null; }
        }
        return new(r.Family, r.Source, normalized, r.Destination, r.OutputInterface, Action: action,
            InputInterface: r.InputInterface, Protocol: r.Protocol, DestinationPort: r.DestinationPort, DestinationPorts: r.DestinationPorts,
            NegateSource: r.NegateSource, NegateDestination: r.NegateDestination, NegateInputInterface: r.NegateInputInterface, NegateOutputInterface: r.NegateOutputInterface,
            SourcePrefixes: r.SourcePrefixes, DestinationPrefixes: r.DestinationPrefixes, CountPackets: countPackets,
            MatchOriginalDestinationDnat: matchDnat, OriginalSourcePrefixes: originalSources, OriginalDestinationPrefixes: originalDestinations,
            InputInterfaceSelector: r.InputInterfaceSelector, OutputInterfaceSelector: r.OutputInterfaceSelector);
    }

    private static FilterRule? ParsePacketMatchers(JsonArray nodes, IpFamily? originalFamily)
    {
        nodes.Add(JsonNode.Parse("{\"accept\":null}"));
        var rule = Parse(nodes);
        if (rule is not null || originalFamily is null) { return rule; }

        // nft can omit nfproto when the original tuple alone establishes the IP family.
        // The address matcher providing that evidence must still be consumed in its exact position.
        nodes.Insert(0, new JsonObject
        {
            ["match"] = new JsonObject
            {
                ["op"] = "==",
                ["left"] = new JsonObject { ["meta"] = new JsonObject { ["key"] = "nfproto" } },
                ["right"] = originalFamily == IpFamily.IPv4 ? "ipv4" : "ipv6"
            }
        });
        return Parse(nodes);

        static FilterRule? Parse(JsonArray matchers)
        {
            using var doc = JsonDocument.Parse(matchers.ToJsonString());
            return NftTableObservation.ParseFilterMatchers(doc.RootElement);
        }
    }

    // Only a counter immediately before the action can be reconstructed without changing what it counts.
    private static bool TryReadCounter(JsonElement expressions, out int matchCount, out bool countPackets)
    {
        matchCount = expressions.GetArrayLength() - 1;
        countPackets = matchCount > 0 && NftJsonHelpers.Properties(expressions[matchCount - 1], "counter");
        if (!countPackets) { return true; }

        matchCount--;
        var counter = expressions[matchCount].GetProperty("counter");
        if (!NftJsonHelpers.Properties(counter, "packets", "bytes")) { return false; }
        var packets = counter.GetProperty("packets");
        var bytes = counter.GetProperty("bytes");
        return packets.ValueKind == JsonValueKind.Number && packets.TryGetUInt64(out _) &&
            bytes.ValueKind == JsonValueKind.Number && bytes.TryGetUInt64(out _);
    }

    private static NftNatObservationResult Deny(string code) => new(null, code);
}

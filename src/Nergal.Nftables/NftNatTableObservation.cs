using System.Globalization;
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
        ulong postroutingChainHandle,
        NatPolicy policy,
        List<(ulong Handle, DnatRule Rule)> dnatRules,
        List<(ulong Handle, SnatRule Rule)> snatRules)
    {
        Identity = identity;
        TableHandle = tableHandle;
        PreroutingChainHandle = preroutingChainHandle;
        PostroutingChainHandle = postroutingChainHandle;
        Policy = policy;

        var projection = new StringBuilder(string.Join('\n',
            "nergal-nat-observation-v1",
            identity.Comment,
            tableHandle.ToString(CultureInfo.InvariantCulture),
            string.Join(' ', preroutingChainHandle.ToString(CultureInfo.InvariantCulture), "inet", NftNatCompiler.TableName, "prerouting", "nat", "prerouting", "-100", "accept"),
            string.Join(' ', postroutingChainHandle.ToString(CultureInfo.InvariantCulture), "inet", NftNatCompiler.TableName, "postrouting", "nat", "postrouting", "100", "accept")));

        foreach (var (handle, rule) in dnatRules)
        {
            projection.Append('\n')
                .Append(handle.ToString(CultureInfo.InvariantCulture)).Append(" dnat ")
                .Append(rule.Family == IpFamily.IPv4 ? "ipv4 " : "ipv6 ")
                .Append(rule.InputInterface ?? "-").Append(' ')
                .Append(rule.Source?.Value ?? "-").Append(' ')
                .Append(rule.OriginalDestination.Value).Append(' ')
                .Append(rule.Protocol).Append(' ')
                .Append(rule.OriginalPort?.ToString(CultureInfo.InvariantCulture) ?? "-").Append(' ')
                .Append(rule.TranslatedAddress).Append(' ')
                .Append(rule.TranslatedPort?.ToString(CultureInfo.InvariantCulture) ?? "-");
        }

        foreach (var (handle, rule) in snatRules)
        {
            projection.Append('\n')
                .Append(handle.ToString(CultureInfo.InvariantCulture)).Append(" snat ")
                .Append(rule.Family == IpFamily.IPv4 ? "ipv4 " : "ipv6 ")
                .Append(rule.OutputInterface ?? "-").Append(' ')
                .Append(rule.Source.Value).Append(' ')
                .Append(rule.Destination?.Value ?? "-").Append(' ')
                .Append(rule.TranslatedAddress);
        }

        StateDigest = CandidateDigest.FromText(projection.ToString());
    }

    /// <summary>Gets the canonical owner/resource marker parsed from the table comment.</summary>
    public NftTableIdentity Identity { get; }

    /// <summary>Gets the positive native table handle.</summary>
    public ulong TableHandle { get; }

    /// <summary>Gets the positive native prerouting chain handle.</summary>
    public ulong PreroutingChainHandle { get; }

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

            var items = root.GetProperty("nftables").EnumerateArray().ToArray();
            JsonElement table, preChain, postChain;
            int ruleStartIndex;
            if (isEcho)
            {
                if (items.Length < 3 ||
                    !NftJsonHelpers.Properties(items[0], "create") || !NftJsonHelpers.Properties(items[0].GetProperty("create"), "table") ||
                    !NftJsonHelpers.Properties(items[1], "add") || !NftJsonHelpers.Properties(items[1].GetProperty("add"), "chain") ||
                    !NftJsonHelpers.Properties(items[2], "add") || !NftJsonHelpers.Properties(items[2].GetProperty("add"), "chain"))
                {
                    return Deny("observation.replacementEcho");
                }

                table = items[0].GetProperty("create").GetProperty("table");
                preChain = items[1].GetProperty("add").GetProperty("chain");
                postChain = items[2].GetProperty("add").GetProperty("chain");
                ruleStartIndex = 3;
            }
            else
            {
                if (items.Length < 4 || !NftJsonHelpers.Properties(items[0], "metainfo"))
                {
                    return Deny("observation.unsupportedObjects");
                }

                if (!NftJsonHelpers.TryReadMetaHeader(items))
                {
                    return Deny("observation.schema");
                }

                if (!NftJsonHelpers.Properties(items[1], "table") ||
                    !NftJsonHelpers.Properties(items[2], "chain") ||
                    !NftJsonHelpers.Properties(items[3], "chain"))
                {
                    return Deny("observation.unsupportedObjects");
                }

                table = items[1].GetProperty("table");
                preChain = items[2].GetProperty("chain");
                postChain = items[3].GetProperty("chain");
                ruleStartIndex = 4;
            }

            if (!NftJsonHelpers.Properties(table, "family", "name", "handle", "comment") ||
                !NftJsonHelpers.Properties(preChain, "family", "table", "name", "handle", "type", "hook", "prio", "policy") ||
                !NftJsonHelpers.Properties(postChain, "family", "table", "name", "handle", "type", "hook", "prio", "policy"))
            {
                return Deny("observation.fields");
            }

            if (table.GetProperty("family").GetString() != "inet" || table.GetProperty("name").GetString() != NftNatCompiler.TableName ||
                !ValidateChain(preChain, "prerouting", -100) ||
                !ValidateChain(postChain, "postrouting", 100))
            {
                return Deny("observation.scope");
            }

            if (table.GetProperty("handle").ValueKind != JsonValueKind.Number || !table.GetProperty("handle").TryGetUInt64(out var tableHandle) || tableHandle == 0 ||
                preChain.GetProperty("handle").ValueKind != JsonValueKind.Number || !preChain.GetProperty("handle").TryGetUInt64(out var preHandle) || preHandle == 0 ||
                postChain.GetProperty("handle").ValueKind != JsonValueKind.Number || !postChain.GetProperty("handle").TryGetUInt64(out var postHandle) || postHandle == 0 ||
                preHandle == postHandle)
            {
                return Deny("observation.handle");
            }

            var identity = NftTableIdentity.Parse(table.GetProperty("comment").GetString() ?? "");
            if (identity is null)
            {
                return Deny("observation.identity");
            }

            if (preChain.GetProperty("policy").GetString() != "accept" ||
                postChain.GetProperty("policy").GetString() != "accept")
            {
                return Deny("observation.policy");
            }

            var handles = new HashSet<ulong> { preHandle, postHandle };
            var dnatRules = new List<(ulong Handle, DnatRule Rule)>();
            var snatRules = new List<(ulong Handle, SnatRule Rule)>();
            var inPostrouting = false;

            for (var index = ruleStartIndex; index < items.Length; index++)
            {
                JsonElement rule;
                if (isEcho)
                {
                    if (!NftJsonHelpers.Properties(items[index], "add") || !NftJsonHelpers.Properties(items[index].GetProperty("add"), "rule"))
                    {
                        return Deny("observation.replacementEcho");
                    }

                    rule = items[index].GetProperty("add").GetProperty("rule");
                }
                else
                {
                    if (!NftJsonHelpers.Properties(items[index], "rule"))
                    {
                        return Deny("observation.unsupportedObjects");
                    }

                    rule = items[index].GetProperty("rule");
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

                if (chainName == "prerouting")
                {
                    if (inPostrouting)
                    {
                        return Deny("observation.scope");
                    }

                    var parsed = ParseDnatRule(rule.GetProperty("expr"));
                    if (parsed is null) { return Deny("observation.rule"); }
                    dnatRules.Add((ruleHandle, parsed));
                }
                else if (chainName == "postrouting")
                {
                    inPostrouting = true;
                    var parsed = ParseSnatRule(rule.GetProperty("expr"));
                    if (parsed is null) { return Deny("observation.rule"); }
                    snatRules.Add((ruleHandle, parsed));
                }
                else
                {
                    return Deny("observation.scope");
                }
            }

            var policy = new NatPolicy(NatPolicy.CurrentSchemaVersion,
                dnatRules.Select(entry => entry.Rule),
                snatRules.Select(entry => entry.Rule));
            return new(new(identity, tableHandle, preHandle, postHandle, policy, dnatRules, snatRules), null);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or EncoderFallbackException)
        {
            return Deny("observation.invalidJson");
        }
    }

    private static bool ValidateChain(JsonElement chain, string name, int expectedPrio) =>
        chain.GetProperty("family").GetString() == "inet" &&
        chain.GetProperty("table").GetString() == NftNatCompiler.TableName &&
        chain.GetProperty("name").GetString() == name &&
        chain.GetProperty("type").GetString() == "nat" &&
        chain.GetProperty("hook").GetString() == name &&
        chain.GetProperty("prio").ValueKind == JsonValueKind.Number &&
        chain.GetProperty("prio").TryGetInt32(out var priority) &&
        priority == expectedPrio;

    private static DnatRule? ParseDnatRule(JsonElement expressions)
    {
        if (expressions.ValueKind != JsonValueKind.Array || expressions.GetArrayLength() is < 2 or > 6)
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
        NetworkPrefix? source = null;
        NetworkPrefix? originalDestination = null;
        var protocol = FilterProtocol.Any;
        int? originalPort = null;
        var hasL4Proto = false;
        var stage = -1;

        for (var index = 0; index < count - 1; index++)
        {
            if (!NftJsonHelpers.Properties(expressions[index], "match")) { return null; }
            var match = expressions[index].GetProperty("match");
            if (!NftJsonHelpers.Properties(match, "op", "left", "right") ||
                match.GetProperty("op").ValueKind != JsonValueKind.String ||
                match.GetProperty("op").GetString() != "==")
            {
                return null;
            }

            var left = match.GetProperty("left");
            var right = match.GetProperty("right");
            if (NftJsonHelpers.Properties(left, "meta") && NftJsonHelpers.Properties(left.GetProperty("meta"), "key"))
            {
                var key = left.GetProperty("meta").GetProperty("key");
                if (key.ValueKind != JsonValueKind.String) { return null; }
                var keyName = key.GetString();
                if (keyName == "iifname")
                {
                    if (stage >= 0 || right.ValueKind != JsonValueKind.String) { return null; }
                    var iface = right.GetString();
                    if (!FilterPolicyValidation.IsValidInterfaceName(iface)) { return null; }
                    inputInterface = iface;
                    stage = 0;
                    continue;
                }

                if (keyName == "l4proto")
                {
                    if (stage >= 3 || right.ValueKind != JsonValueKind.String) { return null; }
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
                    var prefix = NftJsonHelpers.ParseNetworkPrefix(right, targetFamily.Value);
                    if (prefix is null) { return null; }
                    if (nextStage == 1) { source = prefix; } else { originalDestination = prefix; }
                    stage = nextStage;
                    continue;
                }

                if (pField == "dport")
                {
                    if (stage >= 3 || pProto is not ("tcp" or "udp") ||
                        right.ValueKind != JsonValueKind.Number || !right.TryGetInt32(out var port) ||
                        port is < 1 or > 65535)
                    {
                        return null;
                    }

                    protocol = pProto == "tcp" ? FilterProtocol.Tcp : FilterProtocol.Udp;
                    originalPort = port;
                    stage = 4;
                    continue;
                }
            }

            return null;
        }

        if (originalDestination is null)
        {
            return null;
        }

        var expectL4Proto = protocol != FilterProtocol.Any && !originalPort.HasValue;
        if (hasL4Proto != expectL4Proto || (translatedPort.HasValue && protocol is not (FilterProtocol.Tcp or FilterProtocol.Udp)))
        {
            return null;
        }

        return new(targetFamily.Value, protocol, originalDestination, normalizedAddr, originalPort, translatedPort, inputInterface, source);
    }

    private static SnatRule? ParseSnatRule(JsonElement expressions)
    {
        if (expressions.ValueKind != JsonValueKind.Array || expressions.GetArrayLength() is < 2 or > 4)
        {
            return null;
        }

        var count = expressions.GetArrayLength();
        var terminal = expressions[count - 1];
        if (!NftJsonHelpers.Properties(terminal, "snat"))
        {
            return null;
        }

        var snat = terminal.GetProperty("snat");
        if (!NftJsonHelpers.Properties(snat, "family", "addr"))
        {
            return null;
        }

        IpFamily? targetFamily = snat.GetProperty("family").GetString() switch
        {
            "ip" => IpFamily.IPv4,
            "ip6" => IpFamily.IPv6,
            _ => null,
        };
        if (targetFamily is null || snat.GetProperty("addr").ValueKind != JsonValueKind.String ||
            !FilterPolicyValidation.TryParseSingleIpAddress(snat.GetProperty("addr").GetString(), out _, out var parsedAddrFamily, out var normalizedAddr) ||
            parsedAddrFamily != targetFamily.Value)
        {
            return null;
        }

        string? outputInterface = null;
        NetworkPrefix? source = null;
        NetworkPrefix? destination = null;
        var stage = -1;

        for (var index = 0; index < count - 1; index++)
        {
            if (!NftJsonHelpers.Properties(expressions[index], "match")) { return null; }
            var match = expressions[index].GetProperty("match");
            if (!NftJsonHelpers.Properties(match, "op", "left", "right") ||
                match.GetProperty("op").ValueKind != JsonValueKind.String ||
                match.GetProperty("op").GetString() != "==")
            {
                return null;
            }

            var left = match.GetProperty("left");
            var right = match.GetProperty("right");
            if (NftJsonHelpers.Properties(left, "meta") && NftJsonHelpers.Properties(left.GetProperty("meta"), "key"))
            {
                var key = left.GetProperty("meta").GetProperty("key");
                if (key.ValueKind != JsonValueKind.String || key.GetString() != "oifname" ||
                    stage >= 0 || right.ValueKind != JsonValueKind.String)
                {
                    return null;
                }

                var iface = right.GetString();
                if (!FilterPolicyValidation.IsValidInterfaceName(iface)) { return null; }
                outputInterface = iface;
                stage = 0;
                continue;
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
                    var prefix = NftJsonHelpers.ParseNetworkPrefix(right, targetFamily.Value);
                    if (prefix is null) { return null; }
                    if (nextStage == 1) { source = prefix; } else { destination = prefix; }
                    stage = nextStage;
                    continue;
                }
            }

            return null;
        }

        if (source is null)
        {
            return null;
        }

        return new(targetFamily.Value, source, normalizedAddr, destination, outputInterface);
    }

    private static NftNatObservationResult Deny(string code) => new(null, code);
}

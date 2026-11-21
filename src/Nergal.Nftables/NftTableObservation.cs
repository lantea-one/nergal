using System.Globalization;
using System.Text;
using System.Text.Json;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

/// <summary>Immutable native observation of one tagged table and supported ordered input rules; never a claim of authority.</summary>
public sealed class NftTableObservation
{
    private NftTableObservation(NftTableIdentity identity, ulong tableHandle, ulong chainHandle, FilterVerdict defaultVerdict,
        List<(ulong Handle, FilterRule Rule)> rules)
    {
        Identity = identity;
        TableHandle = tableHandle;
        ChainHandle = chainHandle;
        Policy = new(1, defaultVerdict, rules.Select(entry => entry.Rule));
        var isFamilyOnly = rules.All(entry => entry.Rule.Protocol == FilterProtocol.Any &&
            entry.Rule.Source is null && entry.Rule.Destination is null && !entry.Rule.DestinationPort.HasValue);
        var version = rules.Count == 0 ? "nergal-observation-v1" : isFamilyOnly ? "nergal-observation-v2" : "nergal-observation-v3";
        var projection = new StringBuilder(string.Join('\n', version, identity.Comment,
            tableHandle.ToString(CultureInfo.InvariantCulture), chainHandle.ToString(CultureInfo.InvariantCulture),
            "inet", NftFilterCompiler.TableName, "input", "filter", "input", "0",
            defaultVerdict == FilterVerdict.Accept ? "accept" : "drop"));
        foreach (var (handle, rule) in rules)
        {
            if (isFamilyOnly)
            {
                projection.Append('\n').Append(handle.ToString(CultureInfo.InvariantCulture))
                    .Append(rule.Family == IpFamily.IPv4 ? " ipv4 " : " ipv6 ")
                    .Append(rule.Verdict == FilterVerdict.Accept ? "accept" : "drop");
            }
            else
            {
                projection.Append('\n').Append(handle.ToString(CultureInfo.InvariantCulture))
                    .Append(rule.Family == IpFamily.IPv4 ? " ipv4 " : " ipv6 ")
                    .Append(rule.Source?.Value ?? "-").Append(' ')
                    .Append(rule.Destination?.Value ?? "-").Append(' ')
                    .Append(ProtocolToken(rule.Protocol)).Append(' ')
                    .Append(rule.DestinationPort?.ToString(CultureInfo.InvariantCulture) ?? "-").Append(' ')
                    .Append(rule.Verdict == FilterVerdict.Accept ? "accept" : "drop");
            }
        }
        StateDigest = CandidateDigest.FromText(projection.ToString());
    }

    /// <summary>Gets the observed canonical marker; it must agree with protected expected enrollment.</summary>
    public NftTableIdentity Identity { get; }
    /// <summary>Gets the positive native table handle.</summary>
    public ulong TableHandle { get; }
    /// <summary>Gets the positive native chain handle, included in the complete state fingerprint.</summary>
    public ulong ChainHandle { get; }
    /// <summary>Gets the observed unmatched-input decision.</summary>
    public FilterVerdict DefaultVerdict => Policy.DefaultVerdict;
    /// <summary>Gets the immutable policy reconstructed from every recognized input rule in native order.</summary>
    public FilterPolicy Policy { get; }
    /// <summary>Gets the deterministic fingerprint of all recognized enforcement/identity fields.</summary>
    public CandidateDigest StateDigest { get; }

    /// <summary>Parses bounded native JSON without host access, accepting empty chains and canonical schema-1 input-filter rules.</summary>
    /// <remarks>Unknown objects, fields, duplicate keys and unsupported rule expressions fail closed. The trusted collector must supply a full table snapshot; omitted kernel objects cannot be detected from JSON alone.</remarks>
    /// <exception cref="ArgumentNullException">JSON is null.</exception>
    public static NftObservationResult Parse(string json) => ParseNative(json, EchoMode.None);

    /// <summary>Reads the handle-bearing echo of a successful local exclusive create of an empty accept baseline.</summary>
    /// <remarks>Caller must establish successful transaction exit and independently compare a complete listing before binding.</remarks>
    public static NftObservationResult ParseEnrollmentEcho(string json) => ParseNative(json, EchoMode.Enrollment);

    /// <summary>Reads the handle-bearing echo of a successful atomic table delete-and-recreate or rule-bearing create batch.</summary>
    /// <remarks>Caller must establish successful transaction exit and independently compare a complete listing before recording receipts.</remarks>
    public static NftObservationResult ParseReplacementEcho(string json) => ParseNative(json, EchoMode.Replacement);

    private enum EchoMode { None, Enrollment, Replacement }

    private static NftObservationResult ParseNative(string json, EchoMode mode)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            if (new UTF8Encoding(false, true).GetByteCount(json) > 65536)
            {
                return Deny("observation.tooLarge");
            }

            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            if (HasDuplicateProperties(document.RootElement))
            {
                return Deny("observation.duplicateProperty");
            }

            var root = document.RootElement;
            if (!Properties(root, "nftables") || root.GetProperty("nftables").ValueKind != JsonValueKind.Array)
            {
                return Deny("observation.shape");
            }

            var items = root.GetProperty("nftables").EnumerateArray().ToArray();
            JsonElement table, chain;
            int ruleStartIndex;
            if (mode == EchoMode.Enrollment)
            {
                if (items.Length != 2 || !Properties(items[0], "create") || !Properties(items[1], "add") ||
                    !Properties(items[0].GetProperty("create"), "table") || !Properties(items[1].GetProperty("add"), "chain"))
                {
                    return Deny("observation.createEcho");
                }

                table = items[0].GetProperty("create").GetProperty("table");
                chain = items[1].GetProperty("add").GetProperty("chain");
                ruleStartIndex = 2;
            }
            else if (mode == EchoMode.Replacement)
            {
                if (items.Length < 2 || !Properties(items[0], "create") || !Properties(items[1], "add") ||
                    !Properties(items[0].GetProperty("create"), "table") || !Properties(items[1].GetProperty("add"), "chain"))
                {
                    return Deny("observation.replacementEcho");
                }

                table = items[0].GetProperty("create").GetProperty("table");
                chain = items[1].GetProperty("add").GetProperty("chain");
                ruleStartIndex = 2;
            }
            else
            {
                if (items.Length < 3 || !Properties(items[0], "metainfo") || !Properties(items[1], "table") || !Properties(items[2], "chain"))
                {
                    return Deny("observation.unsupportedObjects");
                }

                var meta = items[0].GetProperty("metainfo");
                if (!Properties(meta, "version", "release_name", "json_schema_version") ||
                    meta.GetProperty("version").ValueKind != JsonValueKind.String || meta.GetProperty("release_name").ValueKind != JsonValueKind.String ||
                    meta.GetProperty("json_schema_version").ValueKind != JsonValueKind.Number ||
                    !meta.GetProperty("json_schema_version").TryGetInt32(out var version) || version != 1)
                {
                    return Deny("observation.schema");
                }

                table = items[1].GetProperty("table");
                chain = items[2].GetProperty("chain");
                ruleStartIndex = 3;
            }
            if (!Properties(table, "family", "name", "handle", "comment") ||
                !Properties(chain, "family", "table", "name", "handle", "type", "hook", "prio", "policy"))
            {
                return Deny("observation.fields");
            }

            if (table.GetProperty("family").GetString() != "inet" || table.GetProperty("name").GetString() != NftFilterCompiler.TableName ||
                chain.GetProperty("family").GetString() != "inet" || chain.GetProperty("table").GetString() != NftFilterCompiler.TableName ||
                chain.GetProperty("name").GetString() != "input" || chain.GetProperty("type").GetString() != "filter" ||
                chain.GetProperty("hook").GetString() != "input" || chain.GetProperty("prio").ValueKind != JsonValueKind.Number ||
                !chain.GetProperty("prio").TryGetInt32(out var priority) || priority != 0)
            {
                return Deny("observation.scope");
            }

            if (table.GetProperty("handle").ValueKind != JsonValueKind.Number || !table.GetProperty("handle").TryGetUInt64(out var tableHandle) || tableHandle == 0 ||
                chain.GetProperty("handle").ValueKind != JsonValueKind.Number || !chain.GetProperty("handle").TryGetUInt64(out var chainHandle) || chainHandle == 0)
            {
                return Deny("observation.handle");
            }

            var identity = NftTableIdentity.Parse(table.GetProperty("comment").GetString() ?? "");
            if (identity is null)
            {
                return Deny("observation.identity");
            }

            var verdict = chain.GetProperty("policy").GetString();
            if (verdict is not ("accept" or "drop") || (mode == EchoMode.Enrollment && verdict != "accept"))
            {
                return Deny("observation.policy");
            }

            var rules = new List<(ulong Handle, FilterRule Rule)>();
            var handles = new HashSet<ulong> { chainHandle };
            for (var index = ruleStartIndex; index < items.Length; index++)
            {
                JsonElement rule;
                if (mode == EchoMode.Replacement)
                {
                    if (!Properties(items[index], "add") || !Properties(items[index].GetProperty("add"), "rule"))
                    {
                        return Deny("observation.replacementEcho");
                    }

                    rule = items[index].GetProperty("add").GetProperty("rule");
                }
                else
                {
                    if (!Properties(items[index], "rule")) { return Deny("observation.unsupportedObjects"); }
                    rule = items[index].GetProperty("rule");
                }

                if (!Properties(rule, "family", "table", "chain", "handle", "expr")) { return Deny("observation.unsupportedObjects"); }
                if (rule.GetProperty("family").GetString() != "inet" || rule.GetProperty("table").GetString() != NftFilterCompiler.TableName ||
                    rule.GetProperty("chain").GetString() != "input") { return Deny("observation.scope"); }
                if (!rule.GetProperty("handle").TryGetUInt64(out var handle) || handle == 0 || !handles.Add(handle))
                { return Deny("observation.handle"); }
                var parsed = ParseSchema1Rule(rule.GetProperty("expr"));
                if (parsed is null) { return Deny("observation.rule"); }
                rules.Add((handle, parsed));
            }
            return new(new(identity, tableHandle, chainHandle, verdict == "accept" ? FilterVerdict.Accept : FilterVerdict.Drop, rules), null);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or EncoderFallbackException)
        {
            return Deny("observation.invalidJson");
        }
    }

    private static FilterRule? ParseSchema1Rule(JsonElement expressions)
    {
        if (expressions.ValueKind != JsonValueKind.Array || expressions.GetArrayLength() is < 2 or > 5)
        {
            return null;
        }

        var count = expressions.GetArrayLength();
        var terminal = expressions[count - 1];
        var accept = Properties(terminal, "accept");
        if ((!accept && !Properties(terminal, "drop")) ||
            terminal.GetProperty(accept ? "accept" : "drop").ValueKind != JsonValueKind.Null)
        {
            return null;
        }

        IpFamily? family = null;
        NetworkPrefix? source = null;
        NetworkPrefix? destination = null;
        var protocol = FilterProtocol.Any;
        int? destinationPort = null;
        var hasNfproto = false;
        var hasL4Proto = false;
        var stage = -1;

        for (var index = 0; index < count - 1; index++)
        {
            if (!Properties(expressions[index], "match")) { return null; }
            var match = expressions[index].GetProperty("match");
            if (!Properties(match, "op", "left", "right") || match.GetProperty("op").ValueKind != JsonValueKind.String ||
                match.GetProperty("op").GetString() != "==") { return null; }
            var left = match.GetProperty("left");
            var right = match.GetProperty("right");

            if (Properties(left, "meta") && Properties(left.GetProperty("meta"), "key"))
            {
                var keyElement = left.GetProperty("meta").GetProperty("key");
                if (keyElement.ValueKind != JsonValueKind.String) { return null; }
                var key = keyElement.GetString();
                if (key == "nfproto")
                {
                    if (stage >= 0 || right.ValueKind != JsonValueKind.String) { return null; }
                    var parsedFamily = right.GetString() switch
                    {
                        "ipv4" => IpFamily.IPv4,
                        "ipv6" => IpFamily.IPv6,
                        _ => (IpFamily?)null,
                    };
                    if (parsedFamily is null) { return null; }
                    family = parsedFamily;
                    hasNfproto = true;
                    stage = 0;
                    continue;
                }

                if (key == "l4proto")
                {
                    if (stage >= 3 || right.ValueKind != JsonValueKind.String) { return null; }
                    (FilterProtocol Parsed, IpFamily? ImpliedFamily)? l4 = right.GetString() switch
                    {
                        "tcp" => (FilterProtocol.Tcp, null),
                        "udp" => (FilterProtocol.Udp, null),
                        "icmp" => (FilterProtocol.Icmp, IpFamily.IPv4),
                        "ipv6-icmp" => (FilterProtocol.IcmpV6, IpFamily.IPv6),
                        _ => null,
                    };
                    if (l4 is null) { return null; }
                    if (l4.Value.ImpliedFamily is { } required)
                    {
                        if (family is { } existing && existing != required) { return null; }
                        family = required;
                    }

                    protocol = l4.Value.Parsed;
                    hasL4Proto = true;
                    stage = 3;
                    continue;
                }

                return null;
            }

            if (Properties(left, "payload") && Properties(left.GetProperty("payload"), "protocol", "field"))
            {
                var payload = left.GetProperty("payload");
                var protocolElement = payload.GetProperty("protocol");
                var fieldElement = payload.GetProperty("field");
                if (protocolElement.ValueKind != JsonValueKind.String || fieldElement.ValueKind != JsonValueKind.String)
                {
                    return null;
                }

                var payloadProtocol = protocolElement.GetString();
                var field = fieldElement.GetString();
                if (field is "saddr" or "daddr")
                {
                    var nextStage = field == "saddr" ? 1 : 2;
                    if (stage >= nextStage || payloadProtocol is not ("ip" or "ip6")) { return null; }
                    var exprFamily = payloadProtocol == "ip" ? IpFamily.IPv4 : IpFamily.IPv6;
                    if (family is { } existing && existing != exprFamily) { return null; }
                    var prefix = ParseNetworkPrefix(right, exprFamily);
                    if (prefix is null) { return null; }
                    family = exprFamily;
                    if (nextStage == 1) { source = prefix; } else { destination = prefix; }
                    stage = nextStage;
                    continue;
                }

                if (field == "dport")
                {
                    if (stage >= 4 || payloadProtocol is not ("tcp" or "udp") ||
                        right.ValueKind != JsonValueKind.Number || !right.TryGetInt32(out var port) ||
                        port is < 1 or > 65535)
                    {
                        return null;
                    }

                    protocol = payloadProtocol == "tcp" ? FilterProtocol.Tcp : FilterProtocol.Udp;
                    destinationPort = port;
                    stage = 4;
                    continue;
                }
            }

            return null;
        }

        if (family is not { } resolvedFamily)
        {
            return null;
        }

        var expectNfproto = source is null && destination is null &&
            protocol is FilterProtocol.Any or FilterProtocol.Tcp or FilterProtocol.Udp;
        var expectL4Proto = protocol != FilterProtocol.Any && !destinationPort.HasValue;
        if (hasNfproto != expectNfproto || hasL4Proto != expectL4Proto)
        {
            return null;
        }

        if ((protocol == FilterProtocol.Icmp && resolvedFamily != IpFamily.IPv4) ||
            (protocol == FilterProtocol.IcmpV6 && resolvedFamily != IpFamily.IPv6))
        {
            return null;
        }

        return new(resolvedFamily, protocol, accept ? FilterVerdict.Accept : FilterVerdict.Drop, source, destination, destinationPort);
    }

    private static NetworkPrefix? ParseNetworkPrefix(JsonElement right, IpFamily family)
    {
        var maxPrefixLength = family == IpFamily.IPv4 ? 32 : 128;
        string candidate;
        if (right.ValueKind == JsonValueKind.String)
        {
            var address = right.GetString();
            if (string.IsNullOrEmpty(address) || address.Contains('/', StringComparison.Ordinal))
            {
                return null;
            }

            candidate = address + "/" + maxPrefixLength.ToString(CultureInfo.InvariantCulture);
        }
        else if (right.ValueKind == JsonValueKind.Object && Properties(right, "prefix"))
        {
            var prefix = right.GetProperty("prefix");
            if (!Properties(prefix, "addr", "len") ||
                prefix.GetProperty("addr").ValueKind != JsonValueKind.String ||
                prefix.GetProperty("len").ValueKind != JsonValueKind.Number ||
                !prefix.GetProperty("len").TryGetInt32(out var length) ||
                length < 0 || length >= maxPrefixLength)
            {
                return null;
            }

            var address = prefix.GetProperty("addr").GetString();
            if (string.IsNullOrEmpty(address) || address.Contains('/', StringComparison.Ordinal))
            {
                return null;
            }

            candidate = address + "/" + length.ToString(CultureInfo.InvariantCulture);
        }
        else
        {
            return null;
        }

        try
        {
            var parsed = new NetworkPrefix(candidate);
            return parsed.Family == family && parsed.Value == candidate ? parsed : null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static string ProtocolToken(FilterProtocol protocol) => protocol switch
    {
        FilterProtocol.Any => "any",
        FilterProtocol.Tcp => "tcp",
        FilterProtocol.Udp => "udp",
        FilterProtocol.Icmp => "icmp",
        FilterProtocol.IcmpV6 => "ipv6-icmp",
        _ => throw new InvalidOperationException("Unvalidated protocol."),
    };

    private static NftObservationResult Deny(string code) => new(null, code);
    private static bool Properties(JsonElement element, params string[] names) => element.ValueKind == JsonValueKind.Object &&
        element.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).SequenceEqual(names.Order(StringComparer.Ordinal));
    private static bool HasDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name) || HasDuplicateProperties(property.Value))
                {
                    return true;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var value in element.EnumerateArray())
            {
                if (HasDuplicateProperties(value))
                {
                    return true;
                }
            }
        }
        return false;
    }
}

/// <summary>Either a complete immutable observation or a stable denial code, without echoing native input.</summary>
public sealed class NftObservationResult
{
    internal NftObservationResult(NftTableObservation? observation, string? errorCode) { Observation = observation; ErrorCode = errorCode; }
    /// <summary>Gets the complete observation, or null on any validation failure.</summary>
    public NftTableObservation? Observation { get; }
    /// <summary>Gets the stable denial code, or null on success.</summary>
    public string? ErrorCode { get; }
    /// <summary>Gets whether the limited observation contract was fully understood.</summary>
    public bool IsSuccess => Observation is not null;
}

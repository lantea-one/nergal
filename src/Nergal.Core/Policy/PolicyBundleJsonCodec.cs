using System.Buffers;
using System.Text;
using System.Text.Json;

namespace Nergal.Core.Policy;

/// <summary>Structured diagnostic reported while decoding policy or bundle JSON.</summary>
/// <param name="Code">Stable machine-readable error code.</param>
/// <param name="Path">JSON path associated with the error.</param>
public sealed record PolicyJsonDiagnostic(string Code, string Path);

/// <summary>Result of decoding a canonical policy or multi-table bundle JSON payload.</summary>
public sealed class PolicyJsonDecodeResult<T>
{
    internal PolicyJsonDecodeResult(T? value, IReadOnlyList<PolicyJsonDiagnostic> diagnostics)
    {
        Value = value;
        Diagnostics = diagnostics;
    }

    /// <summary>Gets the decoded policy object when valid.</summary>
    public T? Value { get; }

    /// <summary>Gets structured validation diagnostics on failure.</summary>
    public IReadOnlyList<PolicyJsonDiagnostic> Diagnostics { get; }

    /// <summary>Gets whether decoding succeeded.</summary>
    public bool IsSuccess => Value is not null;
}

/// <summary>Canonical UTF-8 JSON codec shared by the web controller authoring service and agent control protocol.</summary>
public static class PolicyBundleJsonCodec
{
    private const int MaximumBundleBytes = 262_144;
    private const int MaximumRulesPerSection = 4096;

    /// <summary>Parses a complete <see cref="FirewallPolicyBundle"/> JSON string with duplicate-key and unknown-property rejection.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="json"/> is null.</exception>
    public static PolicyJsonDecodeResult<FirewallPolicyBundle> DecodeBundle(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        if (string.IsNullOrWhiteSpace(json) || Encoding.UTF8.GetByteCount(json) > MaximumBundleBytes)
        {
            return new(null, [new("bundle.bounds", "bundle")]);
        }

        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 12 });
            var root = doc.RootElement;
            if (HasDuplicateProperties(root) || root.ValueKind != JsonValueKind.Object)
            {
                return new(null, [new("bundle.invalidJson", "bundle")]);
            }

            return TryParseBundleElement(root);
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or FormatException or InvalidOperationException)
        {
            return new(null, [new("bundle.invalidJson", "bundle")]);
        }
    }

    /// <summary>Parses an already-parsed <see cref="JsonElement"/> representing a <see cref="FirewallPolicyBundle"/>.</summary>
    public static PolicyJsonDecodeResult<FirewallPolicyBundle> TryParseBundleElement(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object ||
            !HasOnlyProperties(root, "schemaVersion", "filter", "nat", "bridge") ||
            !root.TryGetProperty("schemaVersion", out var verEl) ||
            verEl.ValueKind != JsonValueKind.Number || !verEl.TryGetInt32(out var version) ||
            !root.TryGetProperty("filter", out var filterEl))
        {
            return new(null, [new("bundle.fields", "bundle")]);
        }

        var filterResult = TryParseFilterElement(filterEl);
        if (!filterResult.IsSuccess)
        {
            return new(null, filterResult.Diagnostics);
        }

        NatPolicy? nat = null;
        if (root.TryGetProperty("nat", out var natEl) && natEl.ValueKind != JsonValueKind.Null)
        {
            var natResult = TryParseNatElement(natEl);
            if (!natResult.IsSuccess)
            {
                return new(null, natResult.Diagnostics);
            }

            nat = natResult.Value;
        }

        BridgePolicy? bridge = null;
        if (root.TryGetProperty("bridge", out var bridgeEl) && bridgeEl.ValueKind != JsonValueKind.Null)
        {
            var bridgeResult = TryParseBridgeElement(bridgeEl);
            if (!bridgeResult.IsSuccess)
            {
                return new(null, bridgeResult.Diagnostics);
            }

            bridge = bridgeResult.Value;
        }

        try
        {
            return new(new FirewallPolicyBundle(version, filterResult.Value!, nat, bridge), []);
        }
        catch (Exception ex) when (ex is ArgumentException or ArgumentOutOfRangeException)
        {
            return new(null, [new("bundle.invalid", "bundle")]);
        }
    }

    /// <summary>Parses an already-parsed <see cref="JsonElement"/> representing a <see cref="FilterPolicy"/>.</summary>
    public static PolicyJsonDecodeResult<FilterPolicy> TryParseFilterElement(JsonElement el)
    {
        if (el.ValueKind != JsonValueKind.Object ||
            !HasOnlyProperties(el, "schemaVersion", "inputDefaultVerdict", "forwardDefaultVerdict", "outputDefaultVerdict", "rules") ||
            !el.TryGetProperty("schemaVersion", out var verEl) || verEl.ValueKind != JsonValueKind.Number || !verEl.TryGetInt32(out var version) ||
            !el.TryGetProperty("inputDefaultVerdict", out var inEl) || ParseVerdict(inEl) is not { } inVerdict ||
            !el.TryGetProperty("rules", out var rulesEl) || rulesEl.ValueKind != JsonValueKind.Array || rulesEl.GetArrayLength() > MaximumRulesPerSection)
        {
            return new(null, [new("filter.fields", "filter")]);
        }

        var fwdVerdict = el.TryGetProperty("forwardDefaultVerdict", out var fwdEl)
            ? ParseVerdict(fwdEl)
            : FilterVerdict.Drop;
        var outVerdict = el.TryGetProperty("outputDefaultVerdict", out var outEl)
            ? ParseVerdict(outEl)
            : FilterVerdict.Drop;
        if (fwdVerdict is null || outVerdict is null)
        {
            return new(null, [new("filter.verdict", "filter")]);
        }

        var rules = new List<FilterRule?>(rulesEl.GetArrayLength());
        var index = 0;
        foreach (var item in rulesEl.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object ||
                !HasOnlyProperties(item, "family", "protocol", "verdict", "source", "destination", "destinationPort",
                    "sourcePrefixes", "destinationPrefixes", "destinationPorts",
                    "chain", "inputInterface", "outputInterface", "connectionStates", "icmpType", "rateLimit", "matchOriginalDestinationDnat") ||
                !item.TryGetProperty("family", out var famEl) || ParseFamily(famEl) is not { } family ||
                !item.TryGetProperty("protocol", out var protoEl) || ParseProtocol(protoEl) is not { } protocol ||
                !item.TryGetProperty("verdict", out var verdEl) || ParseVerdict(verdEl) is not { } verdict)
            {
                return new(null, [new("filter.ruleFields", $"filter.rules[{index}]")]);
            }

            var chain = item.TryGetProperty("chain", out var chainEl) ? ParseChain(chainEl) : FilterChainKind.Input;
            if (chain is null)
            {
                return new(null, [new("filter.chain", $"filter.rules[{index}].chain")]);
            }

            var states = ConnectionStateFlags.None;
            if (item.TryGetProperty("connectionStates", out var ctEl) && !TryParseConnectionStates(ctEl, out states))
            {
                return new(null, [new("filter.connectionStates", $"filter.rules[{index}].connectionStates")]);
            }

            NetworkPrefix? src;
            NetworkPrefix? dst;
            try
            {
                src = item.TryGetProperty("source", out var srcEl) && srcEl.ValueKind != JsonValueKind.Null
                    ? (srcEl.ValueKind == JsonValueKind.String ? new NetworkPrefix(srcEl.GetString()!) : throw new FormatException())
                    : null;
                dst = item.TryGetProperty("destination", out var dstEl) && dstEl.ValueKind != JsonValueKind.Null
                    ? (dstEl.ValueKind == JsonValueKind.String ? new NetworkPrefix(dstEl.GetString()!) : throw new FormatException())
                    : null;
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException)
            {
                return new(null, [new("filter.prefix", $"filter.rules[{index}]")]);
            }

            int? dport = null;
            if (item.TryGetProperty("destinationPort", out var dpEl) && dpEl.ValueKind != JsonValueKind.Null)
            {
                if (dpEl.ValueKind != JsonValueKind.Number || !dpEl.TryGetInt32(out var p))
                {
                    return new(null, [new("filter.port", $"filter.rules[{index}].destinationPort")]);
                }

                dport = p;
            }

            if (!TryReadOptionalString(item, "inputInterface", out var iif) ||
                !TryReadOptionalString(item, "outputInterface", out var oif) ||
                !TryReadOptionalString(item, "icmpType", out var icmpType))
            {
                return new(null, [new("filter.ruleFields", $"filter.rules[{index}]")]);
            }

            PerSourceRateLimit? rateLimit = null;
            if (item.TryGetProperty("rateLimit", out var rlEl) && rlEl.ValueKind != JsonValueKind.Null)
            {
                if (rlEl.ValueKind != JsonValueKind.Object ||
                    !HasOnlyProperties(rlEl, "packetsPerWindow", "windowUnit", "burst", "entryTimeoutSeconds") ||
                    !rlEl.TryGetProperty("packetsPerWindow", out var ppwEl) || ppwEl.ValueKind != JsonValueKind.Number || !ppwEl.TryGetInt32(out var ppw) ||
                    !rlEl.TryGetProperty("windowUnit", out var unitEl) || unitEl.ValueKind != JsonValueKind.String ||
                    !rlEl.TryGetProperty("burst", out var burstEl) || burstEl.ValueKind != JsonValueKind.Number || !burstEl.TryGetInt32(out var burst))
                {
                    return new(null, [new("filter.rateLimit", $"filter.rules[{index}].rateLimit")]);
                }

                var timeout = 60;
                if (rlEl.TryGetProperty("entryTimeoutSeconds", out var toEl))
                {
                    if (toEl.ValueKind != JsonValueKind.Number || !toEl.TryGetInt32(out timeout))
                    {
                        return new(null, [new("filter.rateLimit", $"filter.rules[{index}].rateLimit.entryTimeoutSeconds")]);
                    }
                }

                RateLimitTimeUnit? unit = unitEl.GetString() switch
                {
                    "second" => RateLimitTimeUnit.Second,
                    "minute" => RateLimitTimeUnit.Minute,
                    _ => null,
                };
                if (unit is null)
                {
                    return new(null, [new("filter.rateLimitUnit", $"filter.rules[{index}].rateLimit.windowUnit")]);
                }

                try
                {
                    rateLimit = new PerSourceRateLimit(ppw, unit.Value, burst, timeout);
                }
                catch (ArgumentOutOfRangeException)
                {
                    return new(null, [new("filter.rateLimit", $"filter.rules[{index}].rateLimit")]);
                }
            }

            var matchDnat = false;
            if (item.TryGetProperty("matchOriginalDestinationDnat", out var dnatEl))
            {
                if (dnatEl.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                {
                    return new(null, [new("filter.matchDnat", $"filter.rules[{index}].matchOriginalDestinationDnat")]);
                }

                matchDnat = dnatEl.GetBoolean();
            }

            IReadOnlyList<NetworkPrefix>? srcPrefixes = null;
            IReadOnlyList<NetworkPrefix>? dstPrefixes = null;
            if (item.TryGetProperty("sourcePrefixes", out var spEl) && spEl.ValueKind != JsonValueKind.Null)
            {
                if (!TryParsePrefixList(spEl, out srcPrefixes))
                {
                    return new(null, [new("filter.prefixSet", $"filter.rules[{index}].sourcePrefixes")]);
                }
            }

            if (item.TryGetProperty("destinationPrefixes", out var dpSetEl) && dpSetEl.ValueKind != JsonValueKind.Null)
            {
                if (!TryParsePrefixList(dpSetEl, out dstPrefixes))
                {
                    return new(null, [new("filter.prefixSet", $"filter.rules[{index}].destinationPrefixes")]);
                }
            }

            IReadOnlyList<int>? dports = null;
            if (item.TryGetProperty("destinationPorts", out var portsEl) && portsEl.ValueKind != JsonValueKind.Null)
            {
                if (!TryParsePortList(portsEl, out dports))
                {
                    return new(null, [new("filter.portSet", $"filter.rules[{index}].destinationPorts")]);
                }
            }

            rules.Add(new FilterRule(family, protocol, verdict, src, dst, dport, chain.Value, iif, oif, states, icmpType, rateLimit, matchDnat, srcPrefixes, dstPrefixes, dports));
            index++;
        }

        try
        {
            return new(new FilterPolicy(version, inVerdict, fwdVerdict.Value, outVerdict.Value, rules), []);
        }
        catch (Exception ex) when (ex is ArgumentException or ArgumentOutOfRangeException)
        {
            return new(null, [new("filter.invalid", "filter")]);
        }
    }

    /// <summary>Parses an already-parsed <see cref="JsonElement"/> representing a <see cref="NatPolicy"/>.</summary>
    public static PolicyJsonDecodeResult<NatPolicy> TryParseNatElement(JsonElement el)
    {
        if (el.ValueKind != JsonValueKind.Object ||
            !HasOnlyProperties(el, "schemaVersion", "dnatRules", "snatRules") ||
            !el.TryGetProperty("schemaVersion", out var verEl) || verEl.ValueKind != JsonValueKind.Number || !verEl.TryGetInt32(out var version))
        {
            return new(null, [new("nat.fields", "nat")]);
        }

        var dnatRules = new List<DnatRule?>();
        if (el.TryGetProperty("dnatRules", out var dnatEl))
        {
            if (dnatEl.ValueKind != JsonValueKind.Array || dnatEl.GetArrayLength() > 256)
            {
                return new(null, [new("nat.dnatRules", "nat.dnatRules")]);
            }

            var idx = 0;
            foreach (var item in dnatEl.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object ||
                    !HasOnlyProperties(item, "family", "protocol", "originalDestination", "translatedAddress", "originalPort", "translatedPort", "inputInterface", "source") ||
                    !item.TryGetProperty("family", out var famEl) || ParseFamily(famEl) is not { } family ||
                    !item.TryGetProperty("protocol", out var protoEl) || ParseProtocol(protoEl) is not { } protocol ||
                    !item.TryGetProperty("originalDestination", out var odEl) || odEl.ValueKind != JsonValueKind.String ||
                    !item.TryGetProperty("translatedAddress", out var taEl) || taEl.ValueKind != JsonValueKind.String)
                {
                    return new(null, [new("nat.dnatFields", $"nat.dnatRules[{idx}]")]);
                }

                int? origPort = null;
                if (item.TryGetProperty("originalPort", out var opEl) && opEl.ValueKind != JsonValueKind.Null)
                {
                    if (opEl.ValueKind != JsonValueKind.Number || !opEl.TryGetInt32(out var op))
                    {
                        return new(null, [new("nat.port", $"nat.dnatRules[{idx}].originalPort")]);
                    }

                    origPort = op;
                }

                int? transPort = null;
                if (item.TryGetProperty("translatedPort", out var tpEl) && tpEl.ValueKind != JsonValueKind.Null)
                {
                    if (tpEl.ValueKind != JsonValueKind.Number || !tpEl.TryGetInt32(out var tp))
                    {
                        return new(null, [new("nat.port", $"nat.dnatRules[{idx}].translatedPort")]);
                    }

                    transPort = tp;
                }

                if (!TryReadOptionalString(item, "inputInterface", out var dnatIif))
                {
                    return new(null, [new("nat.dnatFields", $"nat.dnatRules[{idx}]")]);
                }

                try
                {
                    var src = item.TryGetProperty("source", out var sEl) && sEl.ValueKind != JsonValueKind.Null
                        ? (sEl.ValueKind == JsonValueKind.String ? new NetworkPrefix(sEl.GetString()!) : throw new FormatException())
                        : null;
                    dnatRules.Add(new DnatRule(family, protocol, new NetworkPrefix(odEl.GetString()!), taEl.GetString()!, origPort, transPort, dnatIif, src));
                }
                catch (Exception ex) when (ex is ArgumentException or FormatException)
                {
                    return new(null, [new("nat.dnatFields", $"nat.dnatRules[{idx}]")]);
                }

                idx++;
            }
        }

        var snatRules = new List<SnatRule?>();
        if (el.TryGetProperty("snatRules", out var snatEl))
        {
            if (snatEl.ValueKind != JsonValueKind.Array || snatEl.GetArrayLength() > 256)
            {
                return new(null, [new("nat.snatRules", "nat.snatRules")]);
            }

            var idx = 0;
            foreach (var item in snatEl.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object ||
                    !HasOnlyProperties(item, "family", "source", "translatedAddress", "destination", "outputInterface") ||
                    !item.TryGetProperty("family", out var famEl) || ParseFamily(famEl) is not { } family ||
                    !item.TryGetProperty("source", out var srcEl) || srcEl.ValueKind != JsonValueKind.String ||
                    !item.TryGetProperty("translatedAddress", out var taEl) || taEl.ValueKind != JsonValueKind.String)
                {
                    return new(null, [new("nat.snatFields", $"nat.snatRules[{idx}]")]);
                }

                if (!TryReadOptionalString(item, "outputInterface", out var snatOif))
                {
                    return new(null, [new("nat.snatFields", $"nat.snatRules[{idx}]")]);
                }

                try
                {
                    var dst = item.TryGetProperty("destination", out var dEl) && dEl.ValueKind != JsonValueKind.Null
                        ? (dEl.ValueKind == JsonValueKind.String ? new NetworkPrefix(dEl.GetString()!) : throw new FormatException())
                        : null;
                    snatRules.Add(new SnatRule(family, new NetworkPrefix(srcEl.GetString()!), taEl.GetString()!, dst, snatOif));
                }
                catch (Exception ex) when (ex is ArgumentException or FormatException)
                {
                    return new(null, [new("nat.snatFields", $"nat.snatRules[{idx}]")]);
                }

                idx++;
            }
        }

        try
        {
            return new(new NatPolicy(version, dnatRules, snatRules), []);
        }
        catch (Exception ex) when (ex is ArgumentException or ArgumentOutOfRangeException)
        {
            return new(null, [new("nat.invalid", "nat")]);
        }
    }

    /// <summary>Parses an already-parsed <see cref="JsonElement"/> representing a <see cref="BridgePolicy"/>.</summary>
    public static PolicyJsonDecodeResult<BridgePolicy> TryParseBridgeElement(JsonElement el)
    {
        if (el.ValueKind != JsonValueKind.Object ||
            !HasOnlyProperties(el, "schemaVersion", "defaultVerdict", "rules") ||
            !el.TryGetProperty("schemaVersion", out var verEl) || verEl.ValueKind != JsonValueKind.Number || !verEl.TryGetInt32(out var version) ||
            !el.TryGetProperty("defaultVerdict", out var defEl) || ParseVerdict(defEl) is not { } defVerdict ||
            !el.TryGetProperty("rules", out var rulesEl) || rulesEl.ValueKind != JsonValueKind.Array || rulesEl.GetArrayLength() > 256)
        {
            return new(null, [new("bridge.fields", "bridge")]);
        }

        var rules = new List<BridgeFilterRule?>();
        var idx = 0;
        foreach (var item in rulesEl.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object ||
                !HasOnlyProperties(item, "etherType", "verdict", "inputInterface", "outputInterface") ||
                !item.TryGetProperty("etherType", out var etEl) || etEl.ValueKind != JsonValueKind.String ||
                !item.TryGetProperty("verdict", out var verdEl) || ParseVerdict(verdEl) is not { } verdict)
            {
                return new(null, [new("bridge.ruleFields", $"bridge.rules[{idx}]")]);
            }

            BridgeEtherType? etherType = etEl.GetString() switch
            {
                "any" => BridgeEtherType.Any,
                "ipv4" => BridgeEtherType.IPv4,
                "ipv6" => BridgeEtherType.IPv6,
                "arp" => BridgeEtherType.Arp,
                _ => null,
            };
            if (etherType is null)
            {
                return new(null, [new("bridge.etherType", $"bridge.rules[{idx}].etherType")]);
            }

            if (!TryReadOptionalString(item, "inputInterface", out var brIif) ||
                !TryReadOptionalString(item, "outputInterface", out var brOif))
            {
                return new(null, [new("bridge.ruleFields", $"bridge.rules[{idx}]")]);
            }

            rules.Add(new BridgeFilterRule(etherType.Value, verdict, brIif, brOif));
            idx++;
        }

        try
        {
            return new(new BridgePolicy(version, defVerdict, rules), []);
        }
        catch (Exception ex) when (ex is ArgumentException or ArgumentOutOfRangeException)
        {
            return new(null, [new("bridge.invalid", "bridge")]);
        }
    }

    /// <summary>Encodes a <see cref="FirewallPolicyBundle"/> into canonical UTF-8 JSON text.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="bundle"/> is null.</exception>
    public static string EncodeBundle(FirewallPolicyBundle bundle, bool indented = true)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = indented });
        WriteBundle(writer, bundle);
        writer.Flush();
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    /// <summary>Writes a <see cref="FirewallPolicyBundle"/> JSON object onto <paramref name="writer"/>.</summary>
    public static void WriteBundle(Utf8JsonWriter writer, FirewallPolicyBundle bundle)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(bundle);
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", bundle.SchemaVersion);
        writer.WritePropertyName("filter");
        WriteFilterPolicy(writer, bundle.Filter);
        if (bundle.Nat is { } nat)
        {
            writer.WritePropertyName("nat");
            WriteNatPolicy(writer, nat);
        }

        if (bundle.Bridge is { } bridge)
        {
            writer.WritePropertyName("bridge");
            WriteBridgePolicy(writer, bridge);
        }

        writer.WriteEndObject();
    }

    /// <summary>Writes a <see cref="FilterPolicy"/> JSON object onto <paramref name="writer"/>.</summary>
    public static void WriteFilterPolicy(Utf8JsonWriter writer, FilterPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(policy);
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", policy.SchemaVersion);
        writer.WriteString("inputDefaultVerdict", VerdictName(policy.InputDefaultVerdict));
        writer.WriteString("forwardDefaultVerdict", VerdictName(policy.ForwardDefaultVerdict));
        writer.WriteString("outputDefaultVerdict", VerdictName(policy.OutputDefaultVerdict));
        writer.WriteStartArray("rules");
        foreach (var r in policy.Rules)
        {
            if (r is null)
            {
                throw new ArgumentException("Null rules cannot be serialized.");
            }

            writer.WriteStartObject();
            writer.WriteString("family", r.Family == IpFamily.IPv4 ? "ipv4" : "ipv6");
            writer.WriteString("protocol", ProtocolName(r.Protocol));
            writer.WriteString("verdict", VerdictName(r.Verdict));
            if (r.Source is not null) { writer.WriteString("source", r.Source.Value); }
            if (r.Destination is not null) { writer.WriteString("destination", r.Destination.Value); }
            if (r.DestinationPort.HasValue) { writer.WriteNumber("destinationPort", r.DestinationPort.Value); }
            if (r.SourcePrefixes is { Count: > 0 })
            {
                writer.WriteStartArray("sourcePrefixes");
                foreach (var p in r.SourcePrefixes) { writer.WriteStringValue(p.Value); }
                writer.WriteEndArray();
            }

            if (r.DestinationPrefixes is { Count: > 0 })
            {
                writer.WriteStartArray("destinationPrefixes");
                foreach (var p in r.DestinationPrefixes) { writer.WriteStringValue(p.Value); }
                writer.WriteEndArray();
            }

            if (r.DestinationPorts is { Count: > 0 })
            {
                writer.WriteStartArray("destinationPorts");
                foreach (var p in r.DestinationPorts) { writer.WriteNumberValue(p); }
                writer.WriteEndArray();
            }
            writer.WriteString("chain", ChainName(r.Chain));
            if (r.InputInterface is not null) { writer.WriteString("inputInterface", r.InputInterface); }
            if (r.OutputInterface is not null) { writer.WriteString("outputInterface", r.OutputInterface); }
            if (r.ConnectionStates != ConnectionStateFlags.None)
            {
                writer.WriteStartArray("connectionStates");
                if ((r.ConnectionStates & ConnectionStateFlags.New) != 0) { writer.WriteStringValue("new"); }
                if ((r.ConnectionStates & ConnectionStateFlags.Established) != 0) { writer.WriteStringValue("established"); }
                if ((r.ConnectionStates & ConnectionStateFlags.Related) != 0) { writer.WriteStringValue("related"); }
                if ((r.ConnectionStates & ConnectionStateFlags.Invalid) != 0) { writer.WriteStringValue("invalid"); }
                writer.WriteEndArray();
            }

            if (r.IcmpType is not null) { writer.WriteString("icmpType", r.IcmpType); }
            if (r.RateLimit is { } rl)
            {
                writer.WriteStartObject("rateLimit");
                writer.WriteNumber("packetsPerWindow", rl.PacketsPerWindow);
                writer.WriteString("windowUnit", rl.WindowUnit == RateLimitTimeUnit.Second ? "second" : "minute");
                writer.WriteNumber("burst", rl.Burst);
                writer.WriteNumber("entryTimeoutSeconds", rl.EntryTimeoutSeconds);
                writer.WriteEndObject();
            }

            if (r.MatchOriginalDestinationDnat) { writer.WriteBoolean("matchOriginalDestinationDnat", true); }
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    /// <summary>Writes a <see cref="NatPolicy"/> JSON object onto <paramref name="writer"/>.</summary>
    public static void WriteNatPolicy(Utf8JsonWriter writer, NatPolicy nat)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(nat);
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", nat.SchemaVersion);
        writer.WriteStartArray("dnatRules");
        foreach (var r in nat.DnatRules)
        {
            if (r is null)
            {
                throw new ArgumentException("Null DNAT rules cannot be serialized.");
            }

            writer.WriteStartObject();
            writer.WriteString("family", r.Family == IpFamily.IPv4 ? "ipv4" : "ipv6");
            writer.WriteString("protocol", ProtocolName(r.Protocol));
            writer.WriteString("originalDestination", r.OriginalDestination.Value);
            writer.WriteString("translatedAddress", r.TranslatedAddress);
            if (r.OriginalPort.HasValue) { writer.WriteNumber("originalPort", r.OriginalPort.Value); }
            if (r.TranslatedPort.HasValue) { writer.WriteNumber("translatedPort", r.TranslatedPort.Value); }
            if (r.InputInterface is not null) { writer.WriteString("inputInterface", r.InputInterface); }
            if (r.Source is not null) { writer.WriteString("source", r.Source.Value); }
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteStartArray("snatRules");
        foreach (var r in nat.SnatRules)
        {
            if (r is null)
            {
                throw new ArgumentException("Null SNAT rules cannot be serialized.");
            }

            writer.WriteStartObject();
            writer.WriteString("family", r.Family == IpFamily.IPv4 ? "ipv4" : "ipv6");
            writer.WriteString("source", r.Source.Value);
            writer.WriteString("translatedAddress", r.TranslatedAddress);
            if (r.Destination is not null) { writer.WriteString("destination", r.Destination.Value); }
            if (r.OutputInterface is not null) { writer.WriteString("outputInterface", r.OutputInterface); }
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    /// <summary>Writes a <see cref="BridgePolicy"/> JSON object onto <paramref name="writer"/>.</summary>
    public static void WriteBridgePolicy(Utf8JsonWriter writer, BridgePolicy bridge)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(bridge);
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", bridge.SchemaVersion);
        writer.WriteString("defaultVerdict", VerdictName(bridge.DefaultVerdict));
        writer.WriteStartArray("rules");
        foreach (var r in bridge.Rules)
        {
            if (r is null)
            {
                throw new ArgumentException("Null bridge rules cannot be serialized.");
            }

            writer.WriteStartObject();
            writer.WriteString("etherType", r.EtherType switch
            {
                BridgeEtherType.Any => "any",
                BridgeEtherType.IPv4 => "ipv4",
                BridgeEtherType.IPv6 => "ipv6",
                BridgeEtherType.Arp => "arp",
                _ => throw new ArgumentOutOfRangeException(nameof(bridge)),
            });
            writer.WriteString("verdict", VerdictName(r.Verdict));
            if (r.InputInterface is not null) { writer.WriteString("inputInterface", r.InputInterface); }
            if (r.OutputInterface is not null) { writer.WriteString("outputInterface", r.OutputInterface); }
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static bool TryParseConnectionStates(JsonElement element, out ConnectionStateFlags states)
    {
        states = ConnectionStateFlags.None;
        if (element.ValueKind == JsonValueKind.Number && element.TryGetInt32(out var raw))
        {
            if (raw < 0 || raw > 15) { return false; }
            states = (ConnectionStateFlags)raw;
            return true;
        }

        if (element.ValueKind != JsonValueKind.Array) { return false; }
        foreach (var item in element.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String) { return false; }
            var flag = item.GetString() switch
            {
                "new" => ConnectionStateFlags.New,
                "established" => ConnectionStateFlags.Established,
                "related" => ConnectionStateFlags.Related,
                "invalid" => ConnectionStateFlags.Invalid,
                _ => (ConnectionStateFlags?)null,
            };
            if (flag is null) { return false; }
            states |= flag.Value;
        }

        return true;
    }

    private static IpFamily? ParseFamily(JsonElement el) => el.ValueKind == JsonValueKind.String ? el.GetString() switch
    {
        "ipv4" => IpFamily.IPv4,
        "ipv6" => IpFamily.IPv6,
        _ => null,
    } : null;

    private static FilterVerdict? ParseVerdict(JsonElement el) => el.ValueKind == JsonValueKind.String ? el.GetString() switch
    {
        "accept" => FilterVerdict.Accept,
        "drop" => FilterVerdict.Drop,
        _ => null,
    } : null;

    private static FilterProtocol? ParseProtocol(JsonElement el) => el.ValueKind == JsonValueKind.String ? el.GetString() switch
    {
        "any" => FilterProtocol.Any,
        "tcp" => FilterProtocol.Tcp,
        "udp" => FilterProtocol.Udp,
        "icmp" => FilterProtocol.Icmp,
        "icmpv6" => FilterProtocol.IcmpV6,
        _ => null,
    } : null;

    private static FilterChainKind? ParseChain(JsonElement el) => el.ValueKind == JsonValueKind.String ? el.GetString() switch
    {
        "input" => FilterChainKind.Input,
        "forward" => FilterChainKind.Forward,
        "output" => FilterChainKind.Output,
        _ => null,
    } : null;

    private static string VerdictName(FilterVerdict v) => v == FilterVerdict.Accept ? "accept" : "drop";

    private static string ProtocolName(FilterProtocol p) => p switch
    {
        FilterProtocol.Any => "any",
        FilterProtocol.Tcp => "tcp",
        FilterProtocol.Udp => "udp",
        FilterProtocol.Icmp => "icmp",
        FilterProtocol.IcmpV6 => "icmpv6",
        _ => throw new ArgumentOutOfRangeException(nameof(p)),
    };

    private static string ChainName(FilterChainKind c) => c switch
    {
        FilterChainKind.Input => "input",
        FilterChainKind.Forward => "forward",
        FilterChainKind.Output => "output",
        _ => throw new ArgumentOutOfRangeException(nameof(c)),
    };

    private static bool TryParsePrefixList(JsonElement el, out IReadOnlyList<NetworkPrefix>? list)
    {
        list = null;
        if (el.ValueKind != JsonValueKind.Array || el.GetArrayLength() > 64)
        {
            return false;
        }

        var items = new List<NetworkPrefix>(el.GetArrayLength());
        foreach (var entry in el.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.String)
            {
                return false;
            }

            try
            {
                items.Add(new NetworkPrefix(entry.GetString()!));
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException)
            {
                return false;
            }
        }

        list = Array.AsReadOnly(items.ToArray());
        return true;
    }

    private static bool TryParsePortList(JsonElement el, out IReadOnlyList<int>? list)
    {
        list = null;
        if (el.ValueKind != JsonValueKind.Array || el.GetArrayLength() > 64)
        {
            return false;
        }

        var items = new List<int>(el.GetArrayLength());
        foreach (var entry in el.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Number || !entry.TryGetInt32(out var p))
            {
                return false;
            }

            items.Add(p);
        }

        list = Array.AsReadOnly(items.ToArray());
        return true;
    }

    private static bool TryReadOptionalString(JsonElement obj, string name, out string? value)
    {
        value = null;
        if (!obj.TryGetProperty(name, out var el) || el.ValueKind == JsonValueKind.Null)
        {
            return true;
        }

        if (el.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        value = el.GetString();
        return true;
    }

    private static bool HasOnlyProperties(JsonElement obj, params string[] allowed)
    {
        if (obj.ValueKind != JsonValueKind.Object) { return false; }
        var set = new HashSet<string>(allowed, StringComparer.Ordinal);
        foreach (var prop in obj.EnumerateObject())
        {
            if (!set.Contains(prop.Name)) { return false; }
        }

        return true;
    }

    private static bool HasDuplicateProperties(JsonElement el)
    {
        if (el.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var p in el.EnumerateObject())
            {
                if (!seen.Add(p.Name) || HasDuplicateProperties(p.Value)) { return true; }
            }
        }
        else if (el.ValueKind == JsonValueKind.Array)
        {
            foreach (var v in el.EnumerateArray())
            {
                if (HasDuplicateProperties(v)) { return true; }
            }
        }

        return false;
    }
}

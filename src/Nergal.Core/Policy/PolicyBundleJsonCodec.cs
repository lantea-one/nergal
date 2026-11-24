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
public static partial class PolicyBundleJsonCodec
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
            !HasOnlyProperties(root, "schemaVersion", "filter", "nat", "bridge", "auxiliaryFilter") ||
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

        AuxiliaryFilterPolicy? auxiliary = null;
        if (root.TryGetProperty("auxiliaryFilter", out var auxEl) && auxEl.ValueKind != JsonValueKind.Null)
        {
            if (!HasOnlyProperties(auxEl, "priority", "filter") || !TryReadOptionalInt(auxEl, "priority", out var priority) || priority is null ||
                !auxEl.TryGetProperty("filter", out var auxFilter)) { return new(null, [new("auxiliary.fields", "auxiliaryFilter")]); }
            var decoded = TryParseFilterElement(auxFilter);
            if (!decoded.IsSuccess) { return new(null, decoded.Diagnostics); }
            auxiliary = new(priority.Value, decoded.Value!);
        }
        try
        {
            return new(new FirewallPolicyBundle(version, filterResult.Value!, nat, bridge, auxiliary), []);
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
            !HasOnlyProperties(el, "schemaVersion", "inputDefaultVerdict", "forwardDefaultVerdict", "outputDefaultVerdict", "rules", "rpFilter", "forwardTcpMssClamp", "forwardTcpMssClampEnabled") ||
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
                    "chain", "inputInterface", "outputInterface", "connectionStates", "icmpType", "rateLimit", "matchOriginalDestinationDnat", "description", "negateInputInterface", "negateOutputInterface", "negateSource", "negateDestination", "sourceMac", "sourceMacs", "negateSourceMac", "sourceObject", "destinationObject", "destinationPortObject", "enabled") || !TryReadEnabled(item, out var enabled) ||
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
                    !HasOnlyProperties(rlEl, "packetsPerWindow", "windowUnit", "burst", "entryTimeoutSeconds", "keyKind") ||
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
                    var key = RateLimitKeyKind.SourceAddress;
                    if (rlEl.TryGetProperty("keyKind", out var keyEl))
                    {
                        if (keyEl.ValueKind != JsonValueKind.String || keyEl.GetString() is not ("sourceAddress" or "destinationAddress"))
                        { return new(null, [new("filter.rateLimitKey", $"filter.rules[{index}].rateLimit.keyKind")]); }
                        key = keyEl.GetString() == "destinationAddress" ? RateLimitKeyKind.DestinationAddress : RateLimitKeyKind.SourceAddress;
                    }
                    rateLimit = new PerSourceRateLimit(ppw, unit.Value, burst, timeout, key);
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

            if (!TryReadOptionalDescription(item, out var description))
            {
                return new(null, [new("filter.description", $"filter.rules[{index}].description")]);
            }

            if (!TryReadRouterMatchers(item, out var router))
            { return new(null, [new("filter.routerFields", $"filter.rules[{index}]")]); }
            if (!TryReadObjectReference(item, "sourceObject", out var sourceObject) ||
                !TryReadObjectReference(item, "destinationObject", out var destinationObject) ||
                !TryReadObjectReference(item, "destinationPortObject", out var portObject))
            { return new(null, [new("filter.objectReference", $"filter.rules[{index}]")]); }
            rules.Add(new FilterRule(family, protocol, verdict, src, dst, dport, chain.Value, iif, oif, states, icmpType, rateLimit, matchDnat, srcPrefixes, dstPrefixes, dports, description,
                router.NegateInputInterface, router.NegateOutputInterface, router.NegateSource, router.NegateDestination,
                router.SourceMac, router.SourceMacs, router.NegateSourceMac, sourceObject, destinationObject, portObject, enabled));
            index++;
        }

        if (!TryReadOptionalInt(el, "forwardTcpMssClamp", out var mss) || !TryReadRpFilter(el, out var rp) || !TryReadEnabled(el, out var mssEnabled, "forwardTcpMssClampEnabled"))
        { return new(null, [new("filter.routerFields", "filter")]); }
        try
        {
            return new(new FilterPolicy(version, inVerdict, fwdVerdict.Value, outVerdict.Value, rules, rp, mss, mssEnabled), []);
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
                    !HasOnlyProperties(item, "family", "protocol", "originalDestination", "translatedAddress", "originalPort", "originalPorts", "originalPortObject", "translatedPort", "inputInterface", "source", "description", "negateSource", "negateDestination", "negateInputInterface", "enabled") || !TryReadEnabled(item, out var enabled) ||
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

                IReadOnlyList<int>? originalPorts = null;
                if (!TryReadObjectReference(item, "originalPortObject", out var originalPortObject) ||
                    (item.TryGetProperty("originalPorts", out var originalPortsElement) && (originalPortsElement.ValueKind == JsonValueKind.Null || !TryParsePortList(originalPortsElement, out originalPorts))))
                { return new(null, [new("nat.dnatFields", $"nat.dnatRules[{idx}]")]); }
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

                if (!TryReadOptionalDescription(item, out var dnatDescription))
                {
                    return new(null, [new("nat.description", $"nat.dnatRules[{idx}].description")]);
                }

                try
                {
                    var src = item.TryGetProperty("source", out var sEl) && sEl.ValueKind != JsonValueKind.Null
                        ? (sEl.ValueKind == JsonValueKind.String ? new NetworkPrefix(sEl.GetString()!) : throw new FormatException())
                        : null;
                    if (!TryReadBool(item, "negateSource", out var ns) || !TryReadBool(item, "negateDestination", out var nd) ||
                        !TryReadBool(item, "negateInputInterface", out var ni)) { return new(null, [new("nat.dnatFields", $"nat.dnatRules[{idx}]")]); }
                    dnatRules.Add(new DnatRule(family, protocol, new NetworkPrefix(odEl.GetString()!), taEl.GetString()!, origPort, transPort, dnatIif, src, dnatDescription, ns, nd, ni, enabled, originalPorts, originalPortObject));
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
                    !HasOnlyProperties(item, "family", "source", "translatedAddress", "destination", "outputInterface", "description",
                        "action", "inputInterface", "protocol", "destinationPort", "destinationPorts", "negateSource", "negateDestination", "negateInputInterface", "negateOutputInterface", "enabled", "destinationPortObject", "sourcePrefixes", "destinationPrefixes", "sourceObject", "destinationObject") || !TryReadEnabled(item, out var enabled) ||
                    !item.TryGetProperty("family", out var famEl) || ParseFamily(famEl) is not { } family)
                {
                    return new(null, [new("nat.snatFields", $"nat.snatRules[{idx}]")]);
                }

                if (!TryReadOptionalString(item, "outputInterface", out var snatOif))
                {
                    return new(null, [new("nat.snatFields", $"nat.snatRules[{idx}]")]);
                }

                if (!TryReadOptionalDescription(item, out var snatDescription))
                {
                    return new(null, [new("nat.description", $"nat.snatRules[{idx}].description")]);
                }

                try
                {
                    var dst = item.TryGetProperty("destination", out var dEl) && dEl.ValueKind != JsonValueKind.Null
                        ? (dEl.ValueKind == JsonValueKind.String ? new NetworkPrefix(dEl.GetString()!) : throw new FormatException())
                        : null;
                    if (!TryReadOptionalString(item, "source", out var source) || !TryReadOptionalString(item, "translatedAddress", out var target) ||
                        !TryReadOptionalString(item, "inputInterface", out var iif) || !TryReadOptionalInt(item, "destinationPort", out var port) ||
                        !TryReadBool(item, "negateSource", out var ns) || !TryReadBool(item, "negateDestination", out var nd) ||
                        !TryReadBool(item, "negateInputInterface", out var ni) || !TryReadBool(item, "negateOutputInterface", out var no))
                    { return new(null, [new("nat.snatFields", $"nat.snatRules[{idx}]")]); }
                    NatPostroutingAction? action = item.TryGetProperty("action", out var actionEl)
                        ? actionEl.ValueKind == JsonValueKind.String ? actionEl.GetString() switch
                        { "snat" => NatPostroutingAction.Snat, "masquerade" => NatPostroutingAction.Masquerade, "return" => NatPostroutingAction.Return, _ => null } : null
                        : NatPostroutingAction.Snat;
                    var protocol = item.TryGetProperty("protocol", out var protoEl) ? ParseProtocol(protoEl) : FilterProtocol.Any;
                    IReadOnlyList<int>? ports = null;
                    if (!TryReadAddressObjectsAndSets(item, out var sourcePrefixes, out var destinationPrefixes, out var sourceObject, out var destinationObject) ||
                        !TryReadObjectReference(item, "destinationPortObject", out var portObject) || action is null || protocol is null ||
                        (item.TryGetProperty("destinationPorts", out var portsEl) && portsEl.ValueKind != JsonValueKind.Null && !TryParsePortList(portsEl, out ports)))
                    { return new(null, [new("nat.snatFields", $"nat.snatRules[{idx}]")]); }
                    snatRules.Add(new SnatRule(family, source is null ? null : new NetworkPrefix(source), target, dst, snatOif, snatDescription,
                        action.Value, iif, protocol.Value, port, ports, ns, nd, ni, no, enabled, portObject, sourcePrefixes, destinationPrefixes, sourceObject, destinationObject));
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
            !HasOnlyProperties(el, "schemaVersion", "defaultVerdict", "rules", "priority", "subChains") ||
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
                !HasOnlyProperties(item, "etherType", "verdict", "inputInterface", "outputInterface", "description", "bridgeName", "sourceMac", "destinationMac", "negateSourceMac", "negateDestinationMac", "family", "source", "destination", "protocol", "destinationPort", "destinationPorts", "jumpTarget", "return", "enabled", "destinationPortObject", "sourcePrefixes", "destinationPrefixes", "sourceObject", "destinationObject") || !TryReadEnabled(item, out var enabled) ||
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

            if (!TryReadOptionalDescription(item, out var bridgeDescription))
            {
                return new(null, [new("bridge.description", $"bridge.rules[{idx}].description")]);
            }

            if (!TryReadBridgeRouterRule(item, new(etherType.Value, verdict, brIif, brOif, bridgeDescription, Enabled: enabled), out var bridgeRule))
            { return new(null, [new("bridge.routerFields", $"bridge.rules[{idx}]")]); }
            rules.Add(bridgeRule);
            idx++;
        }

        if (!TryReadOptionalInt(el, "priority", out var priority) || !TryReadBridgeSubChains(el, out var subChains))
        { return new(null, [new("bridge.routerFields", "bridge")]); }
        try
        {
            return new(new BridgePolicy(version, defVerdict, rules, priority ?? -200, subChains), []);
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

        if (bundle.AuxiliaryFilter is { } auxiliary)
        {
            writer.WriteStartObject("auxiliaryFilter"); writer.WriteNumber("priority", auxiliary.Priority);
            writer.WritePropertyName("filter"); WriteFilterPolicy(writer, auxiliary.Filter); writer.WriteEndObject();
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
        WriteRouterPolicy(writer, policy);
        writer.WriteStartArray("rules");
        foreach (var r in policy.Rules)
        {
            if (r is null)
            {
                throw new ArgumentException("Null rules cannot be serialized.");
            }

            writer.WriteStartObject();
            if (!r.Enabled) { writer.WriteBoolean("enabled", false); }
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
            WriteObjectReference(writer, "sourceObject", r.SourceObject);
            WriteObjectReference(writer, "destinationObject", r.DestinationObject);
            WriteObjectReference(writer, "destinationPortObject", r.DestinationPortObject);
            WriteRouterMatchers(writer, r);
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
                if (!Enum.IsDefined(rl.KeyKind)) { throw new ArgumentOutOfRangeException(nameof(policy)); }
                if (rl.KeyKind == RateLimitKeyKind.DestinationAddress) { writer.WriteString("keyKind", "destinationAddress"); }
                writer.WriteEndObject();
            }

            if (r.MatchOriginalDestinationDnat) { writer.WriteBoolean("matchOriginalDestinationDnat", true); }
            if (!string.IsNullOrWhiteSpace(r.Description)) { writer.WriteString("description", r.Description.Trim()); }
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
            if (!r.Enabled) { writer.WriteBoolean("enabled", false); }
            writer.WriteString("family", r.Family == IpFamily.IPv4 ? "ipv4" : "ipv6");
            writer.WriteString("protocol", ProtocolName(r.Protocol));
            writer.WriteString("originalDestination", r.OriginalDestination.Value);
            writer.WriteString("translatedAddress", r.TranslatedAddress);
            if (r.OriginalPort.HasValue) { writer.WriteNumber("originalPort", r.OriginalPort.Value); }
            if (r.OriginalPorts is { } originalPorts) { writer.WriteStartArray("originalPorts"); foreach (var port in originalPorts) { writer.WriteNumberValue(port); } writer.WriteEndArray(); }
            WriteObjectReference(writer, "originalPortObject", r.OriginalPortObject);
            if (r.TranslatedPort.HasValue) { writer.WriteNumber("translatedPort", r.TranslatedPort.Value); }
            if (r.InputInterface is not null) { writer.WriteString("inputInterface", r.InputInterface); }
            if (r.Source is not null) { writer.WriteString("source", r.Source.Value); }
            if (!string.IsNullOrWhiteSpace(r.Description)) { writer.WriteString("description", r.Description.Trim()); }
            if (r.NegateSource) { writer.WriteBoolean("negateSource", true); }
            if (r.NegateDestination) { writer.WriteBoolean("negateDestination", true); }
            if (r.NegateInputInterface) { writer.WriteBoolean("negateInputInterface", true); }
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
            WritePostroutingAddresses(writer, r);
            if (!r.Enabled) { writer.WriteBoolean("enabled", false); }
            writer.WriteString("family", r.Family == IpFamily.IPv4 ? "ipv4" : "ipv6");
            if (r.Source is not null) { writer.WriteString("source", r.Source.Value); }
            if (r.TranslatedAddress is not null) { writer.WriteString("translatedAddress", r.TranslatedAddress); }
            if (r.Action != NatPostroutingAction.Snat)
            {
                writer.WriteString("action", r.Action switch
                { NatPostroutingAction.Masquerade => "masquerade", NatPostroutingAction.Return => "return", _ => throw new ArgumentOutOfRangeException(nameof(nat)) });
            }
            if (r.InputInterface is not null) { writer.WriteString("inputInterface", r.InputInterface); }
            if (r.Protocol != FilterProtocol.Any) { writer.WriteString("protocol", ProtocolName(r.Protocol)); }
            if (r.DestinationPort is { } port) { writer.WriteNumber("destinationPort", port); }
            if (r.DestinationPorts is { } ports)
            { writer.WriteStartArray("destinationPorts"); foreach (var p in ports) { writer.WriteNumberValue(p); } writer.WriteEndArray(); }
            if (r.NegateSource) { writer.WriteBoolean("negateSource", true); }
            if (r.NegateDestination) { writer.WriteBoolean("negateDestination", true); }
            if (r.NegateInputInterface) { writer.WriteBoolean("negateInputInterface", true); }
            if (r.NegateOutputInterface) { writer.WriteBoolean("negateOutputInterface", true); }
            if (r.Destination is not null) { writer.WriteString("destination", r.Destination.Value); }
            if (r.OutputInterface is not null) { writer.WriteString("outputInterface", r.OutputInterface); }
            if (!string.IsNullOrWhiteSpace(r.Description)) { writer.WriteString("description", r.Description.Trim()); }
            WriteObjectReference(writer, "destinationPortObject", r.DestinationPortObject);
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
        if (bridge.Priority != -200) { writer.WriteNumber("priority", bridge.Priority); }
        if (bridge.SubChains.Count > 0)
        {
            writer.WriteStartArray("subChains");
            foreach (var c in bridge.SubChains)
            {
                writer.WriteStartObject(); writer.WriteString("name", c.Name); writer.WriteStartArray("rules");
                foreach (var r in c.Rules) { WriteBridgeRule(writer, r ?? throw new ArgumentException("Null bridge rule.")); }
                writer.WriteEndArray(); writer.WriteEndObject();
            }
            writer.WriteEndArray();
        }
        writer.WriteStartArray("rules");
        foreach (var r in bridge.Rules)
        {
            if (r is null)
            {
                throw new ArgumentException("Null bridge rules cannot be serialized.");
            }

            WriteBridgeRule(writer, r);
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
    }

    private static void WriteBridgeRule(Utf8JsonWriter writer, BridgeFilterRule r)
    {
        writer.WriteStartObject();
        if (!r.Enabled) { writer.WriteBoolean("enabled", false); }
        writer.WriteString("etherType", r.EtherType switch
        {
            BridgeEtherType.Any => "any",
            BridgeEtherType.IPv4 => "ipv4",
            BridgeEtherType.IPv6 => "ipv6",
            BridgeEtherType.Arp => "arp",
            _ => throw new ArgumentOutOfRangeException(nameof(r)),
        });
        writer.WriteString("verdict", VerdictName(r.Verdict));
        if (r.InputInterface is not null) { writer.WriteString("inputInterface", r.InputInterface); }
        if (r.OutputInterface is not null) { writer.WriteString("outputInterface", r.OutputInterface); }
        if (!string.IsNullOrWhiteSpace(r.Description)) { writer.WriteString("description", r.Description.Trim()); }
        WriteBridgeRouterRule(writer, r);
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
        "reject" => FilterVerdict.Reject,
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

    private static string VerdictName(FilterVerdict v) => v switch
    {
        FilterVerdict.Accept => "accept",
        FilterVerdict.Drop => "drop",
        FilterVerdict.Reject => "reject",
        _ => throw new ArgumentOutOfRangeException(nameof(v)),
    };

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

    private static bool TryReadOptionalDescription(JsonElement obj, out string? value)
    {
        value = null;
        if (!obj.TryGetProperty("description", out var el) || el.ValueKind == JsonValueKind.Null)
        {
            return true;
        }

        if (el.ValueKind != JsonValueKind.String)
        {
            return false;
        }

        var raw = el.GetString();
        if (string.IsNullOrWhiteSpace(raw))
        {
            return true;
        }

        var trimmed = raw.Trim();
        if (trimmed.Length > 160)
        {
            return false;
        }

        foreach (var c in trimmed)
        {
            if (char.IsControl(c))
            {
                return false;
            }
        }

        value = trimmed;
        return true;
    }

    private static bool HasOnlyProperties(JsonElement obj, params string[] allowed)
    {
        if (obj.ValueKind != JsonValueKind.Object) { return false; }
        var set = new HashSet<string>(allowed, StringComparer.Ordinal);
        foreach (var prop in obj.EnumerateObject())
        {
            if (!set.Remove(prop.Name)) { return false; }
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

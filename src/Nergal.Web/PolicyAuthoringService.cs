using System.Buffers;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Nergal.ControllerState;
using Nergal.Core;
using Nergal.Core.Deployment;
using Nergal.Core.Policy;
using Nergal.Nftables;

namespace Nergal.Web;

internal sealed record PolicyEvaluationReport(
    bool IsValid,
    FirewallPolicyBundle? Bundle,
    string? CanonicalJson,
    BackendCompatibilityReport? Compatibility,
    string? CandidateText,
    string? CandidateDigest,
    string? UnifiedDiff,
    IReadOnlyList<PolicyDiagnostic> Diagnostics);

/// <summary>Pure in-memory JSON bundle codec, compatibility check, native candidate compiler preview, and unified line diff builder.</summary>
internal static class PolicyAuthoringService
{
    internal const string DefaultStarterBundleJson = """
        {
          "schemaVersion": 1,
          "filter": {
            "schemaVersion": 2,
            "inputDefaultVerdict": "drop",
            "forwardDefaultVerdict": "drop",
            "outputDefaultVerdict": "accept",
            "rules": [
              {
                "family": "ipv4",
                "protocol": "tcp",
                "verdict": "accept",
                "chain": "input",
                "connectionStates": ["established", "related"]
              }
            ]
          }
        }
        """;

    internal static readonly BackendCapabilities NativeNftablesCapabilities = new(
        "nftables",
        Enum.GetValues<FirewallFeature>());

    internal static PolicyEvaluationReport EvaluateDraft(
        string bundleJson,
        ControllerStateStore? store = null,
        ulong? compareRevision = null,
        BackendCapabilities? targetCapabilities = null)
    {
        if (!TryDecodeBundle(bundleJson, out var bundle, out var parseErrors))
        {
            return new PolicyEvaluationReport(false, null, null, null, null, null, null, parseErrors);
        }

        var compiled = NftPolicyBundleCompiler.Compile(bundle!);
        if (!compiled.IsSuccess || compiled.Candidate is null || compiled.Digest is null)
        {
            return new PolicyEvaluationReport(false, bundle, null, null, null, null, null, compiled.Diagnostics);
        }

        var caps = targetCapabilities ?? NativeNftablesCapabilities;
        var compatibility = BackendCompatibilityEvaluator.Evaluate(bundle!.GetRequiredFeatures(), caps);
        if (!compatibility.IsCompatible)
        {
            var missing = compatibility.UnsupportedFeatures
                .Select(feature => new PolicyDiagnostic("backend.unsupportedFeature", feature.ToString()))
                .ToArray();
            return new PolicyEvaluationReport(false, bundle, null, compatibility, null, null, null, missing);
        }

        var canonical = EncodeBundle(bundle);
        string? baselineCandidate = null;
        var baselineLabel = "empty";
        if (OperatingSystem.IsLinux() && store is not null && compareRevision is { } rev and > 0)
        {
            var prior = store.GetPolicyRevision(rev);
            if (prior is not null && TryDecodeBundle(prior.PolicyJson, out var priorBundle, out _))
            {
                var priorCompiled = NftPolicyBundleCompiler.Compile(priorBundle!);
                if (priorCompiled.IsSuccess)
                {
                    baselineCandidate = priorCompiled.Candidate;
                    baselineLabel = $"revision-{rev.ToString(CultureInfo.InvariantCulture)}";
                }
            }
        }

        var diff = ComputeUnifiedDiff(
            baselineCandidate ?? "",
            compiled.Candidate,
            baselineLabel,
            $"candidate-{compiled.Digest.Value[..8]}");

        return new PolicyEvaluationReport(
            true,
            bundle,
            canonical,
            compatibility,
            compiled.Candidate,
            compiled.Digest.Value,
            diff,
            []);
    }

    internal static bool TryDecodeBundle(string json, out FirewallPolicyBundle? bundle, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        bundle = null;
        if (string.IsNullOrWhiteSpace(json) || Encoding.UTF8.GetByteCount(json) > 65_536)
        {
            diagnostics = [new("bundle.bounds", "bundle")];
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 12 });
            var root = doc.RootElement;
            if (HasDuplicateProperties(root) || root.ValueKind != JsonValueKind.Object)
            {
                diagnostics = [new("bundle.invalidJson", "bundle")];
                return false;
            }

            if (!HasOnlyProperties(root, "schemaVersion", "filter", "nat", "bridge") ||
                !root.TryGetProperty("schemaVersion", out var verEl) ||
                verEl.ValueKind != JsonValueKind.Number || !verEl.TryGetInt32(out var version) ||
                !root.TryGetProperty("filter", out var filterEl))
            {
                diagnostics = [new("bundle.fields", "bundle")];
                return false;
            }

            if (!TryParseFilterPolicy(filterEl, out var filter, out var filterErrors))
            {
                diagnostics = filterErrors;
                return false;
            }

            NatPolicy? nat = null;
            if (root.TryGetProperty("nat", out var natEl) && natEl.ValueKind != JsonValueKind.Null)
            {
                if (!TryParseNatPolicy(natEl, out nat, out var natErrors))
                {
                    diagnostics = natErrors;
                    return false;
                }
            }

            BridgePolicy? bridge = null;
            if (root.TryGetProperty("bridge", out var bridgeEl) && bridgeEl.ValueKind != JsonValueKind.Null)
            {
                if (!TryParseBridgePolicy(bridgeEl, out bridge, out var bridgeErrors))
                {
                    diagnostics = bridgeErrors;
                    return false;
                }
            }

            bundle = new FirewallPolicyBundle(version, filter!, nat, bridge);
            diagnostics = [];
            return true;
        }
        catch (Exception ex) when (ex is JsonException or ArgumentException or FormatException or InvalidOperationException)
        {
            diagnostics = [new("bundle.invalidJson", "bundle")];
            return false;
        }
    }

    internal static string EncodeBundle(FirewallPolicyBundle bundle)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true });
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
        writer.Flush();
        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    internal static string ComputeUnifiedDiff(string before, string after, string beforeLabel, string afterLabel)
    {
        var a = SplitLines(before);
        var b = SplitLines(after);
        var n = a.Length;
        var m = b.Length;

        var lcs = new int[n + 1, m + 1];
        for (var i = n - 1; i >= 0; i--)
        {
            for (var j = m - 1; j >= 0; j--)
            {
                lcs[i, j] = string.Equals(a[i], b[j], StringComparison.Ordinal)
                    ? 1 + lcs[i + 1, j + 1]
                    : Math.Max(lcs[i + 1, j], lcs[i, j + 1]);
            }
        }

        var output = new StringBuilder();
        output.Append("--- ").Append(beforeLabel).Append('\n');
        output.Append("+++ ").Append(afterLabel).Append('\n');

        var x = 0;
        var y = 0;
        while (x < n || y < m)
        {
            if (x < n && y < m && string.Equals(a[x], b[y], StringComparison.Ordinal))
            {
                output.Append("  ").Append(a[x]).Append('\n');
                x++;
                y++;
            }
            else if (y < m && (x == n || lcs[x, y + 1] >= lcs[x + 1, y]))
            {
                output.Append("+ ").Append(b[y]).Append('\n');
                y++;
            }
            else
            {
                output.Append("- ").Append(a[x]).Append('\n');
                x++;
            }
        }

        return output.ToString();
    }

    private static string[] SplitLines(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return [];
        }

        return text.TrimEnd('\n').Split('\n');
    }

    private static bool TryParseFilterPolicy(JsonElement el, out FilterPolicy? policy, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        policy = null;
        if (el.ValueKind != JsonValueKind.Object ||
            !HasOnlyProperties(el, "schemaVersion", "inputDefaultVerdict", "forwardDefaultVerdict", "outputDefaultVerdict", "rules") ||
            !el.TryGetProperty("schemaVersion", out var verEl) || verEl.ValueKind != JsonValueKind.Number || !verEl.TryGetInt32(out var version) ||
            !el.TryGetProperty("inputDefaultVerdict", out var inEl) || ParseVerdict(inEl) is not { } inVerdict ||
            !el.TryGetProperty("rules", out var rulesEl) || rulesEl.ValueKind != JsonValueKind.Array || rulesEl.GetArrayLength() > 512)
        {
            diagnostics = [new("filter.fields", "filter")];
            return false;
        }

        var fwdVerdict = el.TryGetProperty("forwardDefaultVerdict", out var fwdEl)
            ? ParseVerdict(fwdEl)
            : FilterVerdict.Drop;
        var outVerdict = el.TryGetProperty("outputDefaultVerdict", out var outEl)
            ? ParseVerdict(outEl)
            : FilterVerdict.Drop;
        if (fwdVerdict is null || outVerdict is null)
        {
            diagnostics = [new("filter.verdict", "filter")];
            return false;
        }

        var rules = new List<FilterRule?>(rulesEl.GetArrayLength());
        var index = 0;
        foreach (var item in rulesEl.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object ||
                !HasOnlyProperties(item, "family", "protocol", "verdict", "source", "destination", "destinationPort",
                    "chain", "inputInterface", "outputInterface", "connectionStates", "icmpType", "rateLimit", "matchOriginalDestinationDnat") ||
                !item.TryGetProperty("family", out var famEl) || ParseFamily(famEl) is not { } family ||
                !item.TryGetProperty("protocol", out var protoEl) || ParseProtocol(protoEl) is not { } protocol ||
                !item.TryGetProperty("verdict", out var verdEl) || ParseVerdict(verdEl) is not { } verdict)
            {
                diagnostics = [new("filter.ruleFields", $"filter.rules[{index}]")];
                return false;
            }

            var chain = item.TryGetProperty("chain", out var chainEl) ? ParseChain(chainEl) : FilterChainKind.Input;
            if (chain is null)
            {
                diagnostics = [new("filter.chain", $"filter.rules[{index}].chain")];
                return false;
            }

            var states = ConnectionStateFlags.None;
            if (item.TryGetProperty("connectionStates", out var ctEl) && !TryParseConnectionStates(ctEl, out states))
            {
                diagnostics = [new("filter.connectionStates", $"filter.rules[{index}].connectionStates")];
                return false;
            }

            var src = item.TryGetProperty("source", out var srcEl) && srcEl.ValueKind != JsonValueKind.Null
                ? new NetworkPrefix(srcEl.GetString()!)
                : null;
            var dst = item.TryGetProperty("destination", out var dstEl) && dstEl.ValueKind != JsonValueKind.Null
                ? new NetworkPrefix(dstEl.GetString()!)
                : null;
            int? dport = null;
            if (item.TryGetProperty("destinationPort", out var dpEl) && dpEl.ValueKind != JsonValueKind.Null)
            {
                if (dpEl.ValueKind != JsonValueKind.Number || !dpEl.TryGetInt32(out var p))
                {
                    diagnostics = [new("filter.port", $"filter.rules[{index}].destinationPort")];
                    return false;
                }

                dport = p;
            }

            var iif = ReadOptionalString(item, "inputInterface");
            var oif = ReadOptionalString(item, "outputInterface");
            var icmpType = ReadOptionalString(item, "icmpType");

            PerSourceRateLimit? rateLimit = null;
            if (item.TryGetProperty("rateLimit", out var rlEl) && rlEl.ValueKind != JsonValueKind.Null)
            {
                if (rlEl.ValueKind != JsonValueKind.Object ||
                    !HasOnlyProperties(rlEl, "packetsPerWindow", "windowUnit", "burst", "entryTimeoutSeconds") ||
                    !rlEl.TryGetProperty("packetsPerWindow", out var ppwEl) || ppwEl.ValueKind != JsonValueKind.Number || !ppwEl.TryGetInt32(out var ppw) ||
                    !rlEl.TryGetProperty("windowUnit", out var unitEl) || unitEl.ValueKind != JsonValueKind.String ||
                    !rlEl.TryGetProperty("burst", out var burstEl) || burstEl.ValueKind != JsonValueKind.Number || !burstEl.TryGetInt32(out var burst))
                {
                    diagnostics = [new("filter.rateLimit", $"filter.rules[{index}].rateLimit")];
                    return false;
                }

                var timeout = rlEl.TryGetProperty("entryTimeoutSeconds", out var toEl) && toEl.TryGetInt32(out var t) ? t : 60;
                RateLimitTimeUnit? unit = unitEl.GetString() switch
                {
                    "second" => RateLimitTimeUnit.Second,
                    "minute" => RateLimitTimeUnit.Minute,
                    _ => null,
                };
                if (unit is null)
                {
                    diagnostics = [new("filter.rateLimitUnit", $"filter.rules[{index}].rateLimit.windowUnit")];
                    return false;
                }

                rateLimit = new PerSourceRateLimit(ppw, unit.Value, burst, timeout);
            }

            var matchDnat = false;
            if (item.TryGetProperty("matchOriginalDestinationDnat", out var dnatEl))
            {
                if (dnatEl.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                {
                    diagnostics = [new("filter.matchDnat", $"filter.rules[{index}].matchOriginalDestinationDnat")];
                    return false;
                }

                matchDnat = dnatEl.GetBoolean();
            }

            rules.Add(new FilterRule(family, protocol, verdict, src, dst, dport, chain.Value, iif, oif, states, icmpType, rateLimit, matchDnat));
            index++;
        }

        policy = new FilterPolicy(version, inVerdict, fwdVerdict.Value, outVerdict.Value, rules);
        diagnostics = [];
        return true;
    }

    private static bool TryParseNatPolicy(JsonElement el, out NatPolicy? nat, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        nat = null;
        if (el.ValueKind != JsonValueKind.Object ||
            !HasOnlyProperties(el, "schemaVersion", "dnatRules", "snatRules") ||
            !el.TryGetProperty("schemaVersion", out var verEl) || verEl.ValueKind != JsonValueKind.Number || !verEl.TryGetInt32(out var version))
        {
            diagnostics = [new("nat.fields", "nat")];
            return false;
        }

        var dnatRules = new List<DnatRule?>();
        if (el.TryGetProperty("dnatRules", out var dnatEl))
        {
            if (dnatEl.ValueKind != JsonValueKind.Array || dnatEl.GetArrayLength() > 256)
            {
                diagnostics = [new("nat.dnatRules", "nat.dnatRules")];
                return false;
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
                    diagnostics = [new("nat.dnatFields", $"nat.dnatRules[{idx}]")];
                    return false;
                }

                int? origPort = item.TryGetProperty("originalPort", out var opEl) && opEl.ValueKind == JsonValueKind.Number && opEl.TryGetInt32(out var op) ? op : null;
                int? transPort = item.TryGetProperty("translatedPort", out var tpEl) && tpEl.ValueKind == JsonValueKind.Number && tpEl.TryGetInt32(out var tp) ? tp : null;
                var src = item.TryGetProperty("source", out var sEl) && sEl.ValueKind == JsonValueKind.String ? new NetworkPrefix(sEl.GetString()!) : null;
                dnatRules.Add(new DnatRule(family, protocol, new NetworkPrefix(odEl.GetString()!), taEl.GetString()!, origPort, transPort, ReadOptionalString(item, "inputInterface"), src));
                idx++;
            }
        }

        var snatRules = new List<SnatRule?>();
        if (el.TryGetProperty("snatRules", out var snatEl))
        {
            if (snatEl.ValueKind != JsonValueKind.Array || snatEl.GetArrayLength() > 256)
            {
                diagnostics = [new("nat.snatRules", "nat.snatRules")];
                return false;
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
                    diagnostics = [new("nat.snatFields", $"nat.snatRules[{idx}]")];
                    return false;
                }

                var dst = item.TryGetProperty("destination", out var dEl) && dEl.ValueKind == JsonValueKind.String ? new NetworkPrefix(dEl.GetString()!) : null;
                snatRules.Add(new SnatRule(family, new NetworkPrefix(srcEl.GetString()!), taEl.GetString()!, dst, ReadOptionalString(item, "outputInterface")));
                idx++;
            }
        }

        nat = new NatPolicy(version, dnatRules, snatRules);
        diagnostics = [];
        return true;
    }

    private static bool TryParseBridgePolicy(JsonElement el, out BridgePolicy? bridge, out IReadOnlyList<PolicyDiagnostic> diagnostics)
    {
        bridge = null;
        if (el.ValueKind != JsonValueKind.Object ||
            !HasOnlyProperties(el, "schemaVersion", "defaultVerdict", "rules") ||
            !el.TryGetProperty("schemaVersion", out var verEl) || verEl.ValueKind != JsonValueKind.Number || !verEl.TryGetInt32(out var version) ||
            !el.TryGetProperty("defaultVerdict", out var defEl) || ParseVerdict(defEl) is not { } defVerdict ||
            !el.TryGetProperty("rules", out var rulesEl) || rulesEl.ValueKind != JsonValueKind.Array || rulesEl.GetArrayLength() > 256)
        {
            diagnostics = [new("bridge.fields", "bridge")];
            return false;
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
                diagnostics = [new("bridge.ruleFields", $"bridge.rules[{idx}]")];
                return false;
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
                diagnostics = [new("bridge.etherType", $"bridge.rules[{idx}].etherType")];
                return false;
            }

            rules.Add(new BridgeFilterRule(etherType.Value, verdict, ReadOptionalString(item, "inputInterface"), ReadOptionalString(item, "outputInterface")));
            idx++;
        }

        bridge = new BridgePolicy(version, defVerdict, rules);
        diagnostics = [];
        return true;
    }

    private static void WriteFilterPolicy(Utf8JsonWriter writer, FilterPolicy policy)
    {
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", policy.SchemaVersion);
        writer.WriteString("inputDefaultVerdict", VerdictName(policy.InputDefaultVerdict));
        writer.WriteString("forwardDefaultVerdict", VerdictName(policy.ForwardDefaultVerdict));
        writer.WriteString("outputDefaultVerdict", VerdictName(policy.OutputDefaultVerdict));
        writer.WriteStartArray("rules");
        foreach (var r in policy.Rules)
        {
            if (r is null) { continue; }
            writer.WriteStartObject();
            writer.WriteString("family", r.Family == IpFamily.IPv4 ? "ipv4" : "ipv6");
            writer.WriteString("protocol", ProtocolName(r.Protocol));
            writer.WriteString("verdict", VerdictName(r.Verdict));
            if (r.Source is not null) { writer.WriteString("source", r.Source.Value); }
            if (r.Destination is not null) { writer.WriteString("destination", r.Destination.Value); }
            if (r.DestinationPort.HasValue) { writer.WriteNumber("destinationPort", r.DestinationPort.Value); }
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

    private static void WriteNatPolicy(Utf8JsonWriter writer, NatPolicy nat)
    {
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", nat.SchemaVersion);
        writer.WriteStartArray("dnatRules");
        foreach (var r in nat.DnatRules)
        {
            if (r is null) { continue; }
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
            if (r is null) { continue; }
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

    private static void WriteBridgePolicy(Utf8JsonWriter writer, BridgePolicy bridge)
    {
        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion", bridge.SchemaVersion);
        writer.WriteString("defaultVerdict", VerdictName(bridge.DefaultVerdict));
        writer.WriteStartArray("rules");
        foreach (var r in bridge.Rules)
        {
            if (r is null) { continue; }
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
            var cast = (ConnectionStateFlags)raw;
            if ((cast & ~FilterPolicyValidation.AllConnectionStates) != 0) { return false; }
            states = cast;
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

    private static string? ReadOptionalString(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String ? el.GetString() : null;

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

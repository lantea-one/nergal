using System.Text.Json;

namespace Nergal.Core.Policy;

public static partial class PolicyBundleJsonCodec
{
    private static bool TryReadBool(JsonElement item, string name, out bool value)
    {
        value = false;
        if (!item.TryGetProperty(name, out var el)) { return true; }
        if (el.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) { return false; }
        value = el.GetBoolean();
        return true;
    }

    private static bool TryReadOptionalInt(JsonElement item, string name, out int? value)
    {
        value = null;
        if (!item.TryGetProperty(name, out var el) || el.ValueKind == JsonValueKind.Null) { return true; }
        if (el.ValueKind != JsonValueKind.Number || !el.TryGetInt32(out var number)) { return false; }
        value = number;
        return true;
    }

    private static bool TryReadRouterMatchers(JsonElement item, out FilterRule rule)
    {
        rule = new(IpFamily.IPv4, FilterProtocol.Any, FilterVerdict.Drop);
        if (!TryReadBool(item, "negateInputInterface", out var ni) ||
            !TryReadBool(item, "negateOutputInterface", out var no) ||
            !TryReadBool(item, "negateSource", out var ns) ||
            !TryReadBool(item, "negateDestination", out var nd) ||
            !TryReadBool(item, "negateSourceMac", out var nm)) { return false; }
        MacAddress? mac = null;
        if (item.TryGetProperty("sourceMac", out var macEl) && macEl.ValueKind != JsonValueKind.Null &&
            (macEl.ValueKind != JsonValueKind.String || !MacAddress.TryParse(macEl.GetString(), out mac))) { return false; }
        IReadOnlyList<MacAddress>? macs = null;
        if (item.TryGetProperty("sourceMacs", out var list) && list.ValueKind != JsonValueKind.Null)
        {
            if (list.ValueKind != JsonValueKind.Array || list.GetArrayLength() > 64) { return false; }
            var values = new List<MacAddress>();
            foreach (var entry in list.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.String || !MacAddress.TryParse(entry.GetString(), out var parsed)) { return false; }
                values.Add(parsed!);
            }
            macs = Array.AsReadOnly(values.ToArray());
        }
        rule = rule with
        {
            NegateInputInterface = ni,
            NegateOutputInterface = no,
            NegateSource = ns,
            NegateDestination = nd,
            SourceMac = mac,
            SourceMacs = macs,
            NegateSourceMac = nm
        };
        return true;
    }

    private static bool TryReadRawChain(JsonElement filter, string property, out RpFilterPolicy? policy)
    {
        policy = null;
        if (!filter.TryGetProperty(property, out var el) || el.ValueKind == JsonValueKind.Null) { return true; }
        if (!HasOnlyProperties(el, "defaultVerdict", "rules") ||
            !el.TryGetProperty("defaultVerdict", out var verdictEl) || ParseVerdict(verdictEl) is not { } verdict ||
            !el.TryGetProperty("rules", out var rulesEl) || rulesEl.ValueKind != JsonValueKind.Array || rulesEl.GetArrayLength() > 4096) { return false; }
        var rules = new List<RpFilterRule?>();
        foreach (var item in rulesEl.EnumerateArray())
        {
            if (!HasOnlyProperties(item, "verdict", "family", "protocol", "source", "negateSource", "inputInterface", "negateInputInterface", "outputInterface", "negateOutputInterface", "sourcePort", "destinationPort", "matchFibUnreachable", "notrack", "description", "enabled") || !TryReadEnabled(item, out var enabled) ||
                !item.TryGetProperty("verdict", out var vEl) || ParseFilterRuleVerdict(vEl) is not { } v ||
                !TryReadBool(item, "negateSource", out var ns) || !TryReadBool(item, "negateInputInterface", out var ni) ||
                !TryReadBool(item, "negateOutputInterface", out var no) || !TryReadOptionalString(item, "outputInterface", out var oif) ||
                !TryReadBool(item, "notrack", out var notrack) ||
                !TryReadBool(item, "matchFibUnreachable", out var fib) || !TryReadOptionalString(item, "inputInterface", out var iif) ||
                !TryReadOptionalString(item, "source", out var source) || !TryReadOptionalInt(item, "sourcePort", out var sport) ||
                !TryReadOptionalInt(item, "destinationPort", out var dport) || !TryReadOptionalDescription(item, out var description)) { return false; }
            IpFamily? family = null;
            if (item.TryGetProperty("family", out var fEl) && fEl.ValueKind != JsonValueKind.Null)
            { family = ParseFamily(fEl); if (family is null) { return false; } }
            var protocol = item.TryGetProperty("protocol", out var pEl) ? ParseProtocol(pEl) : FilterProtocol.Any;
            if (protocol is null) { return false; }
            try { rules.Add(new(v, family, protocol.Value, source is null ? null : new NetworkPrefix(source), ns, iif, ni, sport, dport, fib, description, enabled, notrack, oif, no)); }
            catch (ArgumentException) { return false; }
        }
        policy = new(verdict, rules);
        return true;
    }

    private static void WriteRouterMatchers(Utf8JsonWriter w, FilterRule r)
    {
        if (r.NegateInputInterface) { w.WriteBoolean("negateInputInterface", true); }
        if (r.NegateOutputInterface) { w.WriteBoolean("negateOutputInterface", true); }
        if (r.NegateSource) { w.WriteBoolean("negateSource", true); }
        if (r.NegateDestination) { w.WriteBoolean("negateDestination", true); }
        if (r.NegateSourceMac) { w.WriteBoolean("negateSourceMac", true); }
        if (r.SourceMac is not null) { w.WriteString("sourceMac", r.SourceMac.Value); }
        if (r.SourceMacs is not null)
        {
            w.WriteStartArray("sourceMacs");
            foreach (var mac in r.SourceMacs) { w.WriteStringValue(mac.Value); }
            w.WriteEndArray();
        }
    }

    private static void WriteRouterPolicy(Utf8JsonWriter w, FilterPolicy policy)
    {
        if (!policy.ForwardTcpMssClampEnabled) { w.WriteBoolean("forwardTcpMssClampEnabled", false); }
        if (policy.ForwardTcpMssClamp is { } mss) { w.WriteNumber("forwardTcpMssClamp", mss); }
        WriteRawChain(w, "rpFilter", policy.RpFilter);
        WriteRawChain(w, "rawOutput", policy.RawOutput);
    }

    private static void WriteRawChain(Utf8JsonWriter w, string property, RpFilterPolicy? rp)
    {
        if (rp is null) { return; }
        w.WriteStartObject(property);
        w.WriteString("defaultVerdict", VerdictName(rp.DefaultVerdict));
        w.WriteStartArray("rules");
        foreach (var draft in rp.Rules)
        {
            var r = draft ?? throw new ArgumentException("Null rpfilter rules cannot be serialized.");
            w.WriteStartObject();
            if (!r.Enabled) { w.WriteBoolean("enabled", false); }
            w.WriteString("verdict", VerdictName(r.Verdict));
            if (r.Family is { } family) { w.WriteString("family", family == IpFamily.IPv4 ? "ipv4" : "ipv6"); }
            if (r.Protocol != FilterProtocol.Any) { w.WriteString("protocol", ProtocolName(r.Protocol)); }
            if (r.Source is not null) { w.WriteString("source", r.Source.Value); }
            if (r.InputInterface is not null) { w.WriteString("inputInterface", r.InputInterface); }
            if (r.NegateSource) { w.WriteBoolean("negateSource", true); }
            if (r.NegateInputInterface) { w.WriteBoolean("negateInputInterface", true); }
            if (r.OutputInterface is not null) { w.WriteString("outputInterface", r.OutputInterface); }
            if (r.NegateOutputInterface) { w.WriteBoolean("negateOutputInterface", true); }
            if (r.Notrack) { w.WriteBoolean("notrack", true); }
            if (r.SourcePort is { } sport) { w.WriteNumber("sourcePort", sport); }
            if (r.DestinationPort is { } dport) { w.WriteNumber("destinationPort", dport); }
            if (r.MatchFibUnreachable) { w.WriteBoolean("matchFibUnreachable", true); }
            if (r.Description is not null) { w.WriteString("description", r.Description); }
            w.WriteEndObject();
        }
        w.WriteEndArray();
        w.WriteEndObject();
    }
}

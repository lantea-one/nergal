using System.Globalization;
using System.Text;
using System.Text.Json;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

public sealed partial class NftTableObservation
{
    internal static FilterRule? ParseFilterMatchers(JsonElement expressions)
    {
        var index = 0;
        var rule = ParseSchema2Rule(expressions, FilterChainKind.Forward, [], ref index, allowCounter: false);
        // NAT projects these matches onto its own rule type. Require every field it can carry.
        return rule is { Ipv6HopLimit: null, PacketLimit: null, Protocol: not FilterProtocol.TcpOrUdp, BindInputInterfaceIndex: false, Family: not IpFamily.DualStack } ? rule : null;
    }

    private static bool HasRouterMatchers(FilterRule r) => r.Verdict is FilterVerdict.Reject or FilterVerdict.RejectPortUnreachable ||
        r.NegateInputInterface || r.NegateOutputInterface || r.NegateSource || r.NegateDestination ||
        r.SourceMac is not null || r.SourceMacs is not null || r.RateLimit?.KeyKind == RateLimitKeyKind.DestinationAddress;

    private static string RouterProjection(FilterRule r) => string.Join('|',
        r.NegateInputInterface, r.NegateOutputInterface, r.NegateSource, r.NegateDestination,
        r.NegateSourceMac, r.SourceMac?.Value ?? "-", r.SourceMacs is null ? "-" : string.Join(',', r.SourceMacs.Select(m => m.Value)),
        r.RateLimit?.KeyKind.ToString() ?? "-");

    private sealed record ObservedRawChain(ulong Handle, FilterVerdict DefaultVerdict)
    {
        internal List<(ulong Handle, RpFilterRule Rule)> Rules { get; } = [];
        internal RpFilterPolicy ToPolicy() => new(DefaultVerdict, Rules.Select(r => r.Rule));

        internal void AppendProjection(StringBuilder projection, bool output)
        {
            projection.Append(Handle.ToString(CultureInfo.InvariantCulture)).Append(' ').Append(VerdictToken(DefaultVerdict));
            foreach (var (handle, rule) in Rules)
            {
                projection.Append('\n').Append(handle.ToString(CultureInfo.InvariantCulture)).Append(' ');
                RouterFilterValidation.AppendRawRule(projection, rule, output);
            }
        }
    }

    private static ObservedRawChain? ParseRawChain(JsonElement chain, HashSet<ulong> handles, bool output)
    {
        if (!Properties(chain, "family", "table", "name", "handle", "type", "hook", "prio", "policy") ||
            chain.GetProperty("family").GetString() != "inet" || chain.GetProperty("table").GetString() != NftFilterCompiler.TableName ||
            chain.GetProperty("name").GetString() != (output ? "raw_output" : "rpfilter") || chain.GetProperty("type").GetString() != "filter" ||
            chain.GetProperty("hook").GetString() != (output ? "output" : "prerouting") || !chain.GetProperty("prio").TryGetInt32(out var prio) || prio != -300 ||
            !TryParseVerdict(chain.GetProperty("policy").GetString(), out var verdict) || (output && verdict != FilterVerdict.Accept) ||
            !chain.GetProperty("handle").TryGetUInt64(out var handle) || handle == 0 || !handles.Add(handle)) { return null; }
        return new(handle, verdict);
    }

    private static bool TryParseMss(JsonElement expr, out int mss)
    {
        mss = 0;
        return TryReadMssValue(expr, out var value) && value.ValueKind == JsonValueKind.Number &&
            value.TryGetInt32(out mss) && mss is >= 536 and <= 1460;
    }

    private static bool IsRouteMssClamp(JsonElement expr) =>
        TryReadMssValue(expr, out var value) && Properties(value, "rt") &&
        Properties(value.GetProperty("rt"), "key") &&
        value.GetProperty("rt").GetProperty("key").ValueEquals("mtu");

    private static bool TryReadMssValue(JsonElement expr, out JsonElement value)
    {
        value = default;
        if (expr.ValueKind != JsonValueKind.Array || expr.GetArrayLength() != 2 || !Properties(expr[0], "match") || !Properties(expr[1], "mangle")) { return false; }
        var match = expr[0].GetProperty("match");
        var mangle = expr[1].GetProperty("mangle");
        if (!(Properties(match, "op", "left", "right") && match.GetProperty("op").GetString() == "in" &&
            Properties(match.GetProperty("left"), "payload") && Properties(match.GetProperty("left").GetProperty("payload"), "protocol", "field") &&
            match.GetProperty("left").GetProperty("payload").GetProperty("protocol").GetString() == "tcp" &&
            match.GetProperty("left").GetProperty("payload").GetProperty("field").GetString() == "flags" &&
            match.GetProperty("right").ValueKind == JsonValueKind.String && match.GetProperty("right").GetString() == "syn" &&
            Properties(mangle, "key", "value") && Properties(mangle.GetProperty("key"), "tcp option") &&
            Properties(mangle.GetProperty("key").GetProperty("tcp option"), "name", "field") &&
            mangle.GetProperty("key").GetProperty("tcp option").GetProperty("name").GetString() == "maxseg" &&
            mangle.GetProperty("key").GetProperty("tcp option").GetProperty("field").GetString() == "size")) { return false; }
        value = mangle.GetProperty("value");
        return true;
    }

    private static RpFilterRule? ParseRawRule(JsonElement expr, bool output)
    {
        if (expr.ValueKind != JsonValueKind.Array || expr.GetArrayLength() is < 1 or > 10) { return null; }
        var terminal = expr[expr.GetArrayLength() - 1];
        var accept = Properties(terminal, "accept") && terminal.GetProperty("accept").ValueKind == JsonValueKind.Null;
        var drop = Properties(terminal, "drop") && terminal.GetProperty("drop").ValueKind == JsonValueKind.Null;
        var notrack = Properties(terminal, "notrack") && terminal.GetProperty("notrack").ValueKind == JsonValueKind.Null;
        if (!accept && !drop && !notrack) { return null; }
        IpFamily? family = null;
        NetworkPrefix? source = null;
        NetworkPrefix? destination = null;
        IReadOnlyList<NetworkPrefix>? sources = null, destinations = null;
        string? iface = null;
        var bindIndex = false;
        var protocol = FilterProtocol.Any;
        int? sport = null;
        int? dport = null;
        var ns = false;
        var negateInterface = false;
        var fib = false;
        var stage = -1;
        var end = expr.GetArrayLength() - 1;
        var countPackets = end > 0 && IsAnonymousCounter(expr[end - 1]);
        if (countPackets && notrack) { return null; }
        if (countPackets) { end--; }
        for (var i = 0; i < end; i++)
        {
            if (!Properties(expr[i], "match")) { return null; }
            var match = expr[i].GetProperty("match");
            if (!Properties(match, "op", "left", "right")) { return null; }
            var op = match.GetProperty("op").GetString();
            if (op is not ("==" or "!=")) { return null; }
            var left = match.GetProperty("left");
            var right = match.GetProperty("right");
            if (Properties(left, "meta") && Properties(left.GetProperty("meta"), "key"))
            {
                var key = left.GetProperty("meta").GetProperty("key").GetString();
                switch (key)
                {
                    case "nfproto":
                        if (stage >= 0 || op != "==") { return null; }
                        family = right.GetString() switch { "ipv4" => IpFamily.IPv4, "ipv6" => IpFamily.IPv6, _ => null };
                        if (family is null) { return null; }
                        stage = 0;
                        break;
                    case "iif" when !output:
                    case "iifname" when !output:
                    case "oifname" when output:
                        if (stage >= 1 || right.ValueKind != JsonValueKind.String || !FilterPolicyValidation.IsValidInterfaceName(right.GetString())) { return null; }
                        bindIndex = key == "iif";
                        if (bindIndex && right.GetString()!.All(char.IsAsciiDigit)) { return null; }
                        iface = right.GetString(); negateInterface = op == "!="; stage = 1;
                        break;
                    case "l4proto":
                        if (stage >= 4 || op != "==") { return null; }
                        protocol = right.GetString() switch { "tcp" => FilterProtocol.Tcp, "udp" => FilterProtocol.Udp, _ => FilterProtocol.Any };
                        if (protocol == FilterProtocol.Any) { return null; }
                        stage = 6;
                        break;
                    default: return null;
                }
            }
            else if (Properties(left, "payload") && Properties(left.GetProperty("payload"), "protocol", "field"))
            {
                var payload = left.GetProperty("payload");
                var proto = payload.GetProperty("protocol").GetString();
                var field = payload.GetProperty("field").GetString();
                if (proto is "ip" or "ip6" && field is "saddr" or "daddr")
                {
                    var isSource = field == "saddr";
                    var rank = isSource ? 2 : 3;
                    var implied = proto == "ip" ? IpFamily.IPv4 : IpFamily.IPv6;
                    if (stage >= rank || (!isSource && op != "==") || (family.HasValue && family != implied)) { return null; }
                    family = implied;
                    if (Properties(right, "set"))
                    {
                        var set = ParseNetworkPrefixSet(right.GetProperty("set"), implied);
                        if (set is null) { return null; }
                        if (isSource) { sources = set; } else { destinations = set; }
                    }
                    else
                    {
                        var scalar = ParseNetworkPrefix(right, implied);
                        if (scalar is null) { return null; }
                        if (isSource) { source = scalar; } else { destination = scalar; }
                    }
                    if (isSource) { ns = op == "!="; }
                    stage = rank;
                }
                else if (proto is "tcp" or "udp" && field is "sport" or "dport")
                {
                    var next = field == "sport" ? 4 : 5;
                    var implied = proto == "tcp" ? FilterProtocol.Tcp : FilterProtocol.Udp;
                    if (stage >= next || op != "==" || (protocol != FilterProtocol.Any && protocol != implied) ||
                        !right.TryGetInt32(out var port) || port is < 1 or > 65535) { return null; }
                    protocol = implied;
                    if (field == "sport") { sport = port; } else { dport = port; }
                    stage = next;
                }
                else { return null; }
            }
            else if (Properties(left, "fib") && Properties(left.GetProperty("fib"), "result", "flags"))
            {
                var lookup = left.GetProperty("fib");
                if (output || stage >= 7 || op != "==" || lookup.GetProperty("result").GetString() != "oif" ||
                    lookup.GetProperty("flags").ValueKind != JsonValueKind.Array ||
                    !lookup.GetProperty("flags").EnumerateArray().Select(e => e.GetString()).SequenceEqual(new[] { "saddr", "iif" }) ||
                    right.ValueKind != JsonValueKind.String || right.GetString() != "0") { return null; }
                fib = true; stage = 7;
            }
            else { return null; }
        }
        var verdict = accept ? FilterVerdict.Accept : drop ? FilterVerdict.Drop : FilterVerdict.Continue;
        return new(verdict, family, protocol, source, ns, output ? null : iface, !output && negateInterface, sport, dport, fib,
            Notrack: notrack, OutputInterface: output ? iface : null, NegateOutputInterface: output && negateInterface,
            CountPackets: countPackets, BindInputInterfaceIndex: bindIndex, SourcePrefixes: sources, Destination: destination, DestinationPrefixes: destinations);
    }
}

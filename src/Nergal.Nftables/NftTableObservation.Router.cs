using System.Globalization;
using System.Text.Json;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

public sealed partial class NftTableObservation
{
    internal static FilterRule? ParseFilterMatchers(JsonElement expressions)
    {
        var index = 0;
        return ParseSchema2Rule(expressions, FilterChainKind.Forward, [], ref index, allowCounter: false);
    }

    private static bool HasRouterMatchers(FilterRule r) => r.Verdict == FilterVerdict.Reject ||
        r.NegateInputInterface || r.NegateOutputInterface || r.NegateSource || r.NegateDestination ||
        r.SourceMac is not null || r.SourceMacs is not null || r.RateLimit?.KeyKind == RateLimitKeyKind.DestinationAddress;

    private static string RouterProjection(FilterRule r) => string.Join('|',
        r.NegateInputInterface, r.NegateOutputInterface, r.NegateSource, r.NegateDestination,
        r.NegateSourceMac, r.SourceMac?.Value ?? "-", r.SourceMacs is null ? "-" : string.Join(',', r.SourceMacs.Select(m => m.Value)),
        r.RateLimit?.KeyKind.ToString() ?? "-");

    private static bool TryParseRawChain(JsonElement chain, HashSet<ulong> handles, out ulong handle, out FilterVerdict verdict)
    {
        handle = 0;
        verdict = FilterVerdict.Accept;
        return Properties(chain, "family", "table", "name", "handle", "type", "hook", "prio", "policy") &&
            chain.GetProperty("family").GetString() == "inet" && chain.GetProperty("table").GetString() == NftFilterCompiler.TableName &&
            chain.GetProperty("name").GetString() == "rpfilter" && chain.GetProperty("type").GetString() == "filter" &&
            chain.GetProperty("hook").GetString() == "prerouting" && chain.GetProperty("prio").TryGetInt32(out var prio) && prio == -300 &&
            chain.GetProperty("handle").TryGetUInt64(out handle) && handle > 0 && handles.Add(handle) &&
            TryParseVerdict(chain.GetProperty("policy").GetString(), out verdict);
    }

    private static bool TryParseMss(JsonElement expr, out int mss)
    {
        mss = 0;
        if (expr.ValueKind != JsonValueKind.Array || expr.GetArrayLength() != 2 || !Properties(expr[0], "match") || !Properties(expr[1], "mangle")) { return false; }
        var match = expr[0].GetProperty("match");
        var mangle = expr[1].GetProperty("mangle");
        return Properties(match, "op", "left", "right") && match.GetProperty("op").GetString() == "in" &&
            Properties(match.GetProperty("left"), "payload") && Properties(match.GetProperty("left").GetProperty("payload"), "protocol", "field") &&
            match.GetProperty("left").GetProperty("payload").GetProperty("protocol").GetString() == "tcp" &&
            match.GetProperty("left").GetProperty("payload").GetProperty("field").GetString() == "flags" &&
            match.GetProperty("right").ValueKind == JsonValueKind.String && match.GetProperty("right").GetString() == "syn" &&
            Properties(mangle, "key", "value") && Properties(mangle.GetProperty("key"), "tcp option") &&
            Properties(mangle.GetProperty("key").GetProperty("tcp option"), "name", "field") &&
            mangle.GetProperty("key").GetProperty("tcp option").GetProperty("name").GetString() == "maxseg" &&
            mangle.GetProperty("key").GetProperty("tcp option").GetProperty("field").GetString() == "size" &&
            mangle.GetProperty("value").TryGetInt32(out mss) && mss is >= 536 and <= 1460;
    }

    private static RpFilterRule? ParseRpFilterRule(JsonElement expr)
    {
        if (expr.ValueKind != JsonValueKind.Array || expr.GetArrayLength() is < 1 or > 8) { return null; }
        var terminal = expr[expr.GetArrayLength() - 1];
        var accept = Properties(terminal, "accept") && terminal.GetProperty("accept").ValueKind == JsonValueKind.Null;
        var drop = Properties(terminal, "drop") && terminal.GetProperty("drop").ValueKind == JsonValueKind.Null;
        if (!accept && !drop) { return null; }
        IpFamily? family = null;
        NetworkPrefix? source = null;
        string? iif = null;
        var protocol = FilterProtocol.Any;
        int? sport = null;
        int? dport = null;
        var ns = false;
        var ni = false;
        var fib = false;
        var stage = -1;
        for (var i = 0; i < expr.GetArrayLength() - 1; i++)
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
                switch (left.GetProperty("meta").GetProperty("key").GetString())
                {
                    case "nfproto":
                        if (stage >= 0 || op != "==") { return null; }
                        family = right.GetString() switch { "ipv4" => IpFamily.IPv4, "ipv6" => IpFamily.IPv6, _ => null };
                        if (family is null) { return null; }
                        stage = 0;
                        break;
                    case "iifname":
                        if (stage >= 1 || right.ValueKind != JsonValueKind.String || !FilterPolicyValidation.IsValidInterfaceName(right.GetString())) { return null; }
                        iif = right.GetString(); ni = op == "!="; stage = 1;
                        break;
                    case "l4proto":
                        if (stage >= 3 || op != "==") { return null; }
                        protocol = right.GetString() switch { "tcp" => FilterProtocol.Tcp, "udp" => FilterProtocol.Udp, _ => FilterProtocol.Any };
                        if (protocol == FilterProtocol.Any) { return null; }
                        stage = 5;
                        break;
                    default: return null;
                }
            }
            else if (Properties(left, "payload") && Properties(left.GetProperty("payload"), "protocol", "field"))
            {
                var payload = left.GetProperty("payload");
                var proto = payload.GetProperty("protocol").GetString();
                var field = payload.GetProperty("field").GetString();
                if (proto is "ip" or "ip6" && field == "saddr")
                {
                    if (stage >= 2) { return null; }
                    var implied = proto == "ip" ? IpFamily.IPv4 : IpFamily.IPv6;
                    if (family is { } f && f != implied) { return null; }
                    family = implied; source = ParseNetworkPrefix(right, implied); ns = op == "!="; stage = 2;
                    if (source is null) { return null; }
                }
                else if (proto is "tcp" or "udp" && field is "sport" or "dport")
                {
                    var next = field == "sport" ? 3 : 4;
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
                if (stage >= 6 || op != "==" || lookup.GetProperty("result").GetString() != "oif" ||
                    lookup.GetProperty("flags").ValueKind != JsonValueKind.Array ||
                    !lookup.GetProperty("flags").EnumerateArray().Select(e => e.GetString()).SequenceEqual(new[] { "saddr", "iif" }) ||
                    right.ValueKind != JsonValueKind.String || right.GetString() != "0") { return null; }
                fib = true; stage = 6;
            }
            else { return null; }
        }
        return new(accept ? FilterVerdict.Accept : FilterVerdict.Drop, family, protocol, source, ns, iif, ni, sport, dport, fib);
    }
}

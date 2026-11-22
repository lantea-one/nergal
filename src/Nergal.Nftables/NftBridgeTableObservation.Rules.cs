using System.Text.Json;
using Nergal.Core.Policy;
using static Nergal.Nftables.NftJsonHelpers;

namespace Nergal.Nftables;

public sealed partial class NftBridgeTableObservation
{
    private static BridgeFilterRule? ParseRule(JsonElement expressions)
    {
        if (expressions.ValueKind != JsonValueKind.Array || expressions.GetArrayLength() is < 1 or > 12) { return null; }
        var terminal = expressions[expressions.GetArrayLength() - 1];
        var verdict = FilterVerdict.Drop;
        var returns = false;
        string? jump = null;
        if (Properties(terminal, "accept") && terminal.GetProperty("accept").ValueKind == JsonValueKind.Null) { verdict = FilterVerdict.Accept; }
        else if (Properties(terminal, "drop") && terminal.GetProperty("drop").ValueKind == JsonValueKind.Null) { }
        else if (Properties(terminal, "return") && terminal.GetProperty("return").ValueKind == JsonValueKind.Null) { returns = true; }
        else if (Properties(terminal, "jump") && Properties(terminal.GetProperty("jump"), "target") && terminal.GetProperty("jump").GetProperty("target").ValueKind == JsonValueKind.String)
        { jump = terminal.GetProperty("jump").GetProperty("target").GetString(); }
        else { return null; }
        var r = new BridgeFilterRule(BridgeEtherType.Any, verdict, JumpTarget: jump, Return: returns);
        var stage = -1;
        var hadProtocol = false;
        for (var i = 0; i < expressions.GetArrayLength() - 1; i++)
        {
            if (!Properties(expressions[i], "match")) { return null; }
            var match = expressions[i].GetProperty("match");
            if (!Properties(match, "op", "left", "right")) { return null; }
            var op = match.GetProperty("op").GetString();
            if (op is not ("==" or "!=")) { return null; }
            var left = match.GetProperty("left"); var right = match.GetProperty("right");
            if (Properties(left, "meta") && Properties(left.GetProperty("meta"), "key"))
            {
                if (op != "==" || right.ValueKind != JsonValueKind.String) { return null; }
                var value = right.GetString();
                switch (left.GetProperty("meta").GetProperty("key").GetString())
                {
                    case "iifname":
                        if (stage >= 0 || !FilterPolicyValidation.IsValidInterfaceName(value)) { return null; }
                        r = r with { InputInterface = value }; stage = 0; break;
                    case "oifname":
                        if (stage >= 1 || !FilterPolicyValidation.IsValidInterfaceName(value)) { return null; }
                        r = r with { OutputInterface = value }; stage = 1; break;
                    case "ibrname":
                        if (stage >= 2 || !FilterPolicyValidation.IsValidInterfaceName(value)) { return null; }
                        r = r with { BridgeName = value }; stage = 2; break;
                    case "l4proto":
                        if (stage >= 8 || value is not ("tcp" or "udp")) { return null; }
                        r = r with { Protocol = value == "tcp" ? FilterProtocol.Tcp : FilterProtocol.Udp };
                        hadProtocol = true; stage = 8; break;
                    default: return null;
                }
                continue;
            }
            if (!Properties(left, "payload") || !Properties(left.GetProperty("payload"), "protocol", "field")) { return null; }
            var payload = left.GetProperty("payload");
            var proto = payload.GetProperty("protocol").GetString(); var field = payload.GetProperty("field").GetString();
            if (proto == "ether" && field is "saddr" or "daddr")
            {
                var rank = field == "saddr" ? 3 : 4;
                if (stage >= rank || right.ValueKind != JsonValueKind.String || !MacAddress.TryParse(right.GetString(), out var mac)) { return null; }
                r = field == "saddr" ? r with { SourceMac = mac, NegateSourceMac = op == "!=" } : r with { DestinationMac = mac, NegateDestinationMac = op == "!=" };
                stage = rank; continue;
            }
            if (op != "==") { return null; }
            if (proto == "ether" && field == "type")
            {
                if (stage >= 5 || right.ValueKind != JsonValueKind.String) { return null; }
                BridgeEtherType? type = right.GetString() switch { "ip" => BridgeEtherType.IPv4, "ip6" => BridgeEtherType.IPv6, "arp" => BridgeEtherType.Arp, _ => null };
                if (!type.HasValue) { return null; }
                r = r with { EtherType = type.Value }; stage = 5; continue;
            }
            if (proto is "ip" or "ip6" && field is "saddr" or "daddr")
            {
                var rank = field == "saddr" ? 6 : 7;
                var family = proto == "ip" ? IpFamily.IPv4 : IpFamily.IPv6;
                if (stage >= rank || (r.Family.HasValue && r.Family != family)) { return null; }
                var prefix = ParseNetworkPrefix(right, family);
                if (prefix is null) { return null; }
                r = field == "saddr" ? r with { Family = family, Source = prefix } : r with { Family = family, Destination = prefix };
                stage = rank; continue;
            }
            if (proto is "tcp" or "udp" && field == "dport")
            {
                if (stage >= 8) { return null; } // nft elides redundant meta l4proto before a transport payload.
                var protocol = proto == "tcp" ? FilterProtocol.Tcp : FilterProtocol.Udp;
                if (right.ValueKind == JsonValueKind.Number && right.TryGetInt32(out var port) && port is >= 1 and <= 65535)
                { r = r with { Protocol = protocol, DestinationPort = port }; }
                else if (Properties(right, "set") && right.GetProperty("set").ValueKind == JsonValueKind.Array)
                {
                    var values = new List<int>();
                    foreach (var e in right.GetProperty("set").EnumerateArray())
                    { if (e.ValueKind != JsonValueKind.Number || !e.TryGetInt32(out port) || port is < 1 or > 65535) { return null; } values.Add(port); }
                    if (values.Count is < 2 or > 64 || values.Distinct().Count() != values.Count) { return null; }
                    r = r with { Protocol = protocol, DestinationPorts = values.Order().ToArray() };
                }
                else { return null; }
                stage = 9; continue;
            }
            return null;
        }
        if (hadProtocol != (r.Protocol != FilterProtocol.Any && r.DestinationPort is null && r.DestinationPorts is null)) { return null; }
        return r;
    }
}

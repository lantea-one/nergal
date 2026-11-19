using Nergal.Core.Policy;
using Nergal.Nftables;

// Only synthetic documentation addresses; this program emits text and performs no host operations.
var rules = new List<FilterRule?>();
foreach (var family in Enum.GetValues<IpFamily>())
{
    var address = family == IpFamily.IPv4 ? "192.0.2.1/32" : "2001:db8::1/128";
    rules.Add(new(family, FilterProtocol.Tcp, FilterVerdict.Drop, DestinationPort: 18082));
    rules.Add(new(family, FilterProtocol.Tcp, FilterVerdict.Accept, new(address), new(address)));
    rules.Add(new(family, FilterProtocol.Udp, FilterVerdict.Accept, new(address), new(address), 18081));
    rules.Add(new(family, family == IpFamily.IPv4 ? FilterProtocol.Icmp : FilterProtocol.IcmpV6, FilterVerdict.Accept));
}

var result = NftFilterCompiler.Compile(new(1, FilterVerdict.Drop, rules));
if (!result.IsSuccess)
{
    throw new InvalidOperationException("The fixed fixture policy must compile.");
}

Console.Write(result.Candidate);

using System.Net;

namespace Nergal.Nftables;

public static partial class NativeImportPlanner
{
    private sealed partial class Planner
    {
        // Inline nft interval sets describe a union. Remove redundant members
        // and combine binary siblings only when their parent adds no addresses.
        private static string[] CollapseLiteralNetworks(IEnumerable<string> prefixes)
        {
            var inputs = prefixes.ToArray();
            var networks = new HashSet<IPNetwork>();
            foreach (var network in inputs.Select(IPNetwork.Parse).OrderBy(item => item.PrefixLength))
            {
                var current = network;
                if (networks.Any(parent => parent.PrefixLength <= current.PrefixLength &&
                        parent.Contains(current.BaseAddress))) { continue; }
                while (current.PrefixLength != 0)
                {
                    var length = current.PrefixLength - 1;
                    var bytes = current.BaseAddress.GetAddressBytes();
                    var index = length / 8;
                    var bit = (byte)(1 << (7 - length % 8));
                    bytes[index] ^= bit;
                    var sibling = new IPNetwork(new(bytes), current.PrefixLength);
                    if (!networks.Remove(sibling)) { break; }
                    bytes[index] &= (byte)~bit;
                    current = new(new(bytes), length);
                }
                networks.Add(current);
            }
            return networks.Count == inputs.Length
                ? inputs
                : networks.Select(network => network.ToString()).Order(StringComparer.Ordinal).ToArray();
        }
    }
}

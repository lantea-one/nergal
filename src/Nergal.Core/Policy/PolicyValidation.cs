using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace Nergal.Core.Policy;

/// <summary>Canonical ICMP and ICMPv6 type names accepted by schema-2 filter rules.</summary>
public static class FilterIcmpTypes
{
    /// <summary>IPv4 and IPv6 echo request.</summary>
    public const string EchoRequest = "echo-request";

    /// <summary>IPv4 and IPv6 echo reply.</summary>
    public const string EchoReply = "echo-reply";

    /// <summary>IPv4 and IPv6 destination unreachable.</summary>
    public const string DestinationUnreachable = "destination-unreachable";

    /// <summary>IPv4 and IPv6 time exceeded.</summary>
    public const string TimeExceeded = "time-exceeded";

    /// <summary>IPv6 packet too big (Path MTU Discovery).</summary>
    public const string PacketTooBig = "packet-too-big";

    /// <summary>IPv6 parameter problem.</summary>
    public const string ParameterProblem = "parameter-problem";

    /// <summary>IPv6 Neighbor Discovery router solicitation.</summary>
    public const string NdRouterSolicit = "nd-router-solicit";

    /// <summary>IPv6 Neighbor Discovery router advertisement.</summary>
    public const string NdRouterAdvert = "nd-router-advert";

    /// <summary>IPv6 Neighbor Discovery neighbor solicitation.</summary>
    public const string NdNeighborSolicit = "nd-neighbor-solicit";

    /// <summary>IPv6 Neighbor Discovery neighbor advertisement.</summary>
    public const string NdNeighborAdvert = "nd-neighbor-advert";

    private static readonly FrozenSet<string> Ipv4Types = new[]
    {
        EchoRequest,
        EchoReply,
        DestinationUnreachable,
        TimeExceeded,
    }.ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> Ipv6Types = new[]
    {
        EchoRequest,
        EchoReply,
        DestinationUnreachable,
        PacketTooBig,
        TimeExceeded,
        ParameterProblem,
        NdRouterSolicit,
        NdRouterAdvert,
        NdNeighborSolicit,
        NdNeighborAdvert,
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>Returns whether a string is a canonical ICMP type supported for the specified protocol.</summary>
    /// <param name="protocol">The rule's protocol (`Icmp` or `IcmpV6`).</param>
    /// <param name="icmpType">The candidate canonical ICMP type string.</param>
    public static bool IsSupported(FilterProtocol protocol, string? icmpType)
    {
        if (string.IsNullOrEmpty(icmpType))
        {
            return false;
        }

        return protocol switch
        {
            FilterProtocol.Icmp => Ipv4Types.Contains(icmpType),
            FilterProtocol.IcmpV6 => Ipv6Types.Contains(icmpType),
            _ => false,
        };
    }
}

/// <summary>Deterministic syntactic validation helpers for policy primitives.</summary>
public static class FilterPolicyValidation
{
    /// <summary>Bitwise union of all defined schema-2 connection-tracking states.</summary>
    public const ConnectionStateFlags AllConnectionStates =
        ConnectionStateFlags.New | ConnectionStateFlags.Established | ConnectionStateFlags.Related | ConnectionStateFlags.Invalid;

    /// <summary>Validates a Linux interface name against `IFNAMSIZ - 1` and native token safety rules.</summary>
    /// <param name="interfaceName">A candidate interface name such as `eth0`, `veth-a`, or `br0`.</param>
    public static bool IsValidInterfaceName(string? interfaceName)
    {
        if (string.IsNullOrEmpty(interfaceName) || interfaceName.Length > 15)
        {
            return false;
        }

        var first = interfaceName[0];
        if (!IsAsciiAlphanumeric(first))
        {
            return false;
        }

        foreach (var ch in interfaceName)
        {
            if (!IsAsciiAlphanumeric(ch) && ch is not '.' and not '_' and not '-')
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAsciiAlphanumeric(char ch) =>
        ch is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9');

    /// <summary>Parses a canonical single IPv4 or IPv6 host address without CIDR suffix, scope ID, or mapped IPv4.</summary>
    /// <param name="value">The candidate address text.</param>
    /// <param name="address">The parsed address when valid; otherwise null.</param>
    /// <param name="family">The address family when valid.</param>
    /// <param name="normalized">The canonical lowercase string representation when valid.</param>
    public static bool TryParseSingleIpAddress(
        string? value,
        [NotNullWhen(true)] out IPAddress? address,
        out IpFamily family,
        [NotNullWhen(true)] out string? normalized)
    {
        address = null;
        family = IpFamily.IPv4;
        normalized = null;
        if (string.IsNullOrWhiteSpace(value) || value.Any(char.IsWhiteSpace) ||
            value.Contains('/', StringComparison.Ordinal) || value.Contains('%', StringComparison.Ordinal) ||
            !IPAddress.TryParse(value, out var parsed) || parsed.IsIPv4MappedToIPv6)
        {
            return false;
        }

        if (parsed.AddressFamily == AddressFamily.InterNetwork)
        {
            if (value.Count(ch => ch == '.') != 3)
            {
                return false;
            }

            address = parsed;
            family = IpFamily.IPv4;
            normalized = parsed.ToString();
            return true;
        }

        if (parsed.AddressFamily == AddressFamily.InterNetworkV6)
        {
            address = parsed;
            family = IpFamily.IPv6;
            normalized = parsed.ToString();
            return true;
        }

        return false;
    }
}

using System.Net;
using System.Net.Sockets;

namespace Nergal.Core.Policy;

/// <summary>A canonical numeric CIDR with zero host bits and no scope identifier.</summary>
public sealed record NetworkPrefix
{
    /// <summary>Parses a numeric CIDR; host bits, scoped and mapped addresses are rejected.</summary>
    /// <exception cref="ArgumentException">The text is not a supported network prefix.</exception>
    public NetworkPrefix(string value)
    {
        // Compare the original address: IPNetwork parsing silently masks host bits.
        var separator = value?.IndexOf('/') ?? -1;
        if (string.IsNullOrWhiteSpace(value) || separator < 0 || value.Contains('%') ||
            !IPNetwork.TryParse(value, out var network) || network.BaseAddress.IsIPv4MappedToIPv6 ||
            !IPAddress.TryParse(value[..separator], out var address) || !address.Equals(network.BaseAddress))
        {
            throw new ArgumentException("Expected a numeric CIDR with zero host bits and no scope or mapped address.", nameof(value));
        }

        Family = network.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? IpFamily.IPv4 : IpFamily.IPv6;
        Value = network.ToString();
    }

    /// <summary>Gets the canonical numeric representation used by compilers.</summary>
    public string Value { get; }

    /// <summary>Gets the network's IP family.</summary>
    public IpFamily Family { get; }
}

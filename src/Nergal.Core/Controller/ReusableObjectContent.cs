using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Nergal.Core.Policy;

namespace Nergal.Core.Controller;

/// <summary>Supported static list types; dynamic flags, ranges and timeouts are not implied.</summary>
public enum ReusableObjectKind
{
    /// <summary>Numeric IPv4 addresses and canonical IPv4 CIDRs.</summary>
    Ipv4,
    /// <summary>Numeric IPv6 addresses and canonical IPv6 CIDRs without scopes or mapped addresses.</summary>
    Ipv6,
    /// <summary>Individual transport port numbers, independent of a rule's TCP/UDP selection.</summary>
    Port
}

/// <summary>Immutable validated controller list contents, independent of native execution or persistence.</summary>
public sealed class ReusableObjectContent
{
    /// <summary>Maximum number of distinct entries per version.</summary>
    public const int MaximumEntries = 64;

    /// <summary>Creates a bounded canonical snapshot, copying and sorting caller entries without merging prefixes.</summary>
    /// <exception cref="ArgumentException">Identifier, description, type or entries are invalid; the message is a stable object diagnostic.</exception>
    public ReusableObjectContent(string name, ReusableObjectKind kind, string description, IEnumerable<string> entries)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 64 || name[0] is < 'a' or > 'z' || name.Any(c => c is not (>= 'a' and <= 'z' or >= '0' and <= '9' or '_')))
        { throw new ArgumentException("object.nameInvalid", nameof(name)); }
        if (!Enum.IsDefined(kind)) { throw new ArgumentException("object.kindInvalid", nameof(kind)); }
        if (description is null || description.Length > 500 || description.Any(c => char.IsControl(c) && c is not ('\r' or '\n' or '\t')))
        { throw new ArgumentException("object.descriptionInvalid", nameof(description)); }
        ArgumentNullException.ThrowIfNull(entries);
        var input = entries.Take(MaximumEntries + 1).ToArray();
        if (input.Length is 0 or > MaximumEntries) { throw new ArgumentException("object.entryCountInvalid", nameof(entries)); }
        var normalized = input.Select(e => Normalize(e, kind)).ToArray();
        if (normalized.Distinct(StringComparer.Ordinal).Count() != normalized.Length) { throw new ArgumentException("object.duplicateEntry", nameof(entries)); }
        Name = name; Kind = kind; Description = description;
        Entries = Array.AsReadOnly(normalized.Order(StringComparer.Ordinal).ToArray());
    }

    /// <summary>Gets the stable lowercase identifier, never native syntax or a filesystem path.</summary>
    public string Name { get; }
    /// <summary>Gets the fixed element type.</summary>
    public ReusableObjectKind Kind { get; }
    /// <summary>Gets the plain-text operator description.</summary>
    public string Description { get; }
    /// <summary>Gets a defensive canonical snapshot of the distinct entries.</summary>
    public IReadOnlyList<string> Entries { get; }

    private static string Normalize(string value, ReusableObjectKind kind)
    {
        if (string.IsNullOrEmpty(value) || value.Length > 80 || value != value.Trim()) { throw new ArgumentException("object.entryInvalid"); }
        if (kind == ReusableObjectKind.Port)
        {
            if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535)
            { throw new ArgumentException("object.portInvalid"); }
            return port.ToString(CultureInfo.InvariantCulture);
        }
        var addressText = value.Split('/')[0];
        if (addressText.Contains('%') || !IPAddress.TryParse(addressText, out var address) || address.IsIPv4MappedToIPv6 ||
            (address.AddressFamily == AddressFamily.InterNetwork && address.ToString() != addressText))
        { throw new ArgumentException("object.addressInvalid"); }
        if ((kind == ReusableObjectKind.Ipv4) != (address.AddressFamily == AddressFamily.InterNetwork)) { throw new ArgumentException("object.familyMismatch"); }
        NetworkPrefix prefix;
        try { prefix = new NetworkPrefix(value.Contains('/') ? value : value + (kind == ReusableObjectKind.Ipv4 ? "/32" : "/128")); }
        catch (ArgumentException) { throw new ArgumentException("object.prefixInvalid"); }
        return prefix.Value;
    }
}

/// <summary>A durable immutable object version; editing never mutates this snapshot or any saved policy.</summary>
public sealed record ReusableObjectVersion(Guid Id, int Version, ReusableObjectContent Content, string Digest, string UpdatedByActor, DateTimeOffset UpdatedAtUtc);

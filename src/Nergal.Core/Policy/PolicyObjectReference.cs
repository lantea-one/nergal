using System.Globalization;
using Nergal.Core.Controller;

namespace Nergal.Core.Policy;

/// <summary>A self-contained immutable controller object version, retained in policy JSON independently of future library edits.</summary>
public sealed record PolicyObjectReference
{
    /// <summary>Creates a pinned reference from validated immutable content. No database lookup or native execution occurs.</summary>
    /// <exception cref="ArgumentException">Identity/version is outside the controller object contract.</exception>
    /// <exception cref="ArgumentNullException">Content is null.</exception>
    public PolicyObjectReference(Guid id, int version, ReusableObjectContent content)
    {
        ArgumentNullException.ThrowIfNull(content);
        if (id == Guid.Empty || version is < 1 or > 64) { throw new ArgumentException("object.referenceInvalid"); }
        Id = id; Version = version; Content = content;
    }
    /// <summary>Gets the stable controller object identity.</summary>
    public Guid Id { get; }
    /// <summary>Gets the explicitly selected immutable version.</summary>
    public int Version { get; }
    /// <summary>Gets validated immutable embedded contents; compilation never fetches the latest library version.</summary>
    public ReusableObjectContent Content { get; }
    /// <inheritdoc />
    public bool Equals(PolicyObjectReference? other) => other is not null && Id == other.Id && Version == other.Version && Content.Digest == other.Content.Digest;
    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(Id, Version, Content.Digest);
}

/// <summary>A stable controller-reference validation failure at a matcher path.</summary>
public sealed record PolicyObjectDiagnostic(string Code, string Path);

/// <summary>Resolves static controller snapshots to existing literal matcher contracts, preserving all other rule semantics.</summary>
public static class FilterObjectResolver
{
    /// <summary>Returns a resolved defensive policy and appends diagnostics for conflicting or incompatible references.</summary>
    /// <remarks>References remain on the original intent; only the compiler projection removes metadata. No list elements are merged or omitted.</remarks>
    public static FilterPolicy Resolve(FilterPolicy policy, ICollection<PolicyObjectDiagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(policy); ArgumentNullException.ThrowIfNull(diagnostics);
        if (!policy.Rules.Any(r => r?.SourceObject is not null || r?.DestinationObject is not null || r?.DestinationPortObject is not null)) { return policy; }
        var rules = policy.Rules.Select((r, i) =>
        {
            if (r is null) { return null; }
            var path = "rules[" + i.ToString(CultureInfo.InvariantCulture) + "]";
            if (policy.SchemaVersion != 2) { diagnostics.Add(new("object.requiresSchema2", path)); }
            var source = Prefixes(r.SourceObject, r.Source is not null || r.SourcePrefixes is not null, r.Family, path + ".sourceObject", diagnostics);
            var destination = Prefixes(r.DestinationObject, r.Destination is not null || r.DestinationPrefixes is not null, r.Family, path + ".destinationObject", diagnostics);
            int[]? ports = null;
            if (r.DestinationPortObject is { } reference)
            {
                if (r.DestinationPort is not null || r.DestinationPorts is not null) { diagnostics.Add(new("object.conflictsWithLiteral", path + ".destinationPortObject")); }
                if (reference.Content.Kind != ReusableObjectKind.Port) { diagnostics.Add(new("object.kindMismatch", path + ".destinationPortObject")); }
                else { ports = reference.Content.Entries.Select(p => int.Parse(p, CultureInfo.InvariantCulture)).ToArray(); }
            }
            return r with
            {
                Source = source?.Length == 1 ? source[0] : r.Source,
                SourcePrefixes = source?.Length > 1 ? source : r.SourcePrefixes,
                Destination = destination?.Length == 1 ? destination[0] : r.Destination,
                DestinationPrefixes = destination?.Length > 1 ? destination : r.DestinationPrefixes,
                DestinationPort = ports?.Length == 1 ? ports[0] : r.DestinationPort,
                DestinationPorts = ports?.Length > 1 ? ports : r.DestinationPorts,
                SourceObject = null,
                DestinationObject = null,
                DestinationPortObject = null
            };
        });
        return new(policy.SchemaVersion, policy.InputDefaultVerdict, policy.ForwardDefaultVerdict, policy.OutputDefaultVerdict, rules, policy.RpFilter, policy.ForwardTcpMssClamp);
    }
    private static NetworkPrefix[]? Prefixes(PolicyObjectReference? reference, bool conflict, IpFamily family, string path, ICollection<PolicyObjectDiagnostic> diagnostics)
    {
        if (reference is null) { return null; }
        if (conflict) { diagnostics.Add(new("object.conflictsWithLiteral", path)); }
        var expected = family == IpFamily.IPv4 ? ReusableObjectKind.Ipv4 : ReusableObjectKind.Ipv6;
        if (reference.Content.Kind != expected) { diagnostics.Add(new("object.familyMismatch", path)); return null; }
        return reference.Content.Entries.Select(p => new NetworkPrefix(p)).ToArray();
    }
}

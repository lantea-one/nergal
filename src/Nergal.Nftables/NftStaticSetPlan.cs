using System.Globalization;
using System.Text;
using Nergal.Core.Controller;
using Nergal.Core.Policy;

namespace Nergal.Nftables;

// A native name binds immutable identity/version/type; it contains no user-provided syntax.
internal sealed class NftStaticSetPlan
{
    private readonly SortedDictionary<string, PolicyObjectReference> active = new(StringComparer.Ordinal);
    internal NftStaticSetPlan(IEnumerable<(PolicyObjectReference? Reference, bool Enabled)> references, ICollection<PolicyDiagnostic> errors)
    {
        var snapshots = new Dictionary<(Guid, int), string>();
        foreach (var (reference, enabled) in references)
        {
            if (reference is not { NativeSet: true }) { continue; }
            var key = (reference.Id, reference.Version);
            if (snapshots.TryGetValue(key, out var digest) && digest != reference.Content.Digest)
            { errors.Add(new("object.nativeSnapshotConflict", "objects")); }
            else { snapshots[key] = reference.Content.Digest; }
            if (enabled) { active.TryAdd(Name(reference), reference); }
        }
        if (active.Count > 64) { errors.Add(new("object.tooManyNativeSets", "objects")); }
    }
    // Native echo adds a separate envelope per static element. Reject oversized projections before any privileged write.
    // Canonical emitted tokens are ASCII; the per-line allowance includes maximal numeric handles and object envelopes.
    internal static long Estimate(string candidate, int elements = 0) => checked((long)Encoding.UTF8.GetByteCount(candidate) * 6 + candidate.Count(c => c == '\n') * 128L + elements * 256L);
    internal CompilationResult Finish(string candidate)
    {
        if (active.Count == 0) { return new(candidate, []); }
        var budget = Estimate(candidate, active.Values.Sum(r => r.Content.Entries.Count));
        return budget > NftObservationLimits.MaximumDocumentBytes ? new(null, [new("object.nativeObservationTooLarge", "objects")]) : new(candidate, [], budget);
    }
    internal void Append(StringBuilder text, string family, string table)
    {
        foreach (var (name, reference) in active)
        {
            text.Append("add set ").Append(family).Append(' ').Append(table).Append(' ').Append(name)
                .Append(" { type ").Append(Type(reference.Content.Kind)).Append("; flags constant")
                .Append(reference.Content.Kind == ReusableObjectKind.Port ? "" : ",interval")
                .Append("; elements = { ").Append(string.Join(", ", reference.Content.Entries)).Append(" }; }\n");
        }
    }
    internal static string Name(PolicyObjectReference reference) => "nergal_obj_" + reference.Id.ToString("N") + "_" +
        reference.Version.ToString(CultureInfo.InvariantCulture) + "_" + SuffixName(reference);
    private static string SuffixName(PolicyObjectReference r) => r.Content.Kind switch
    {
        ReusableObjectKind.Ipv4 => "4",
        ReusableObjectKind.Ipv6 => "6",
        ReusableObjectKind.Port => "p",
        _ => throw new ArgumentException("object.kindInvalid")
    };
    internal static string Type(ReusableObjectKind kind) => kind switch
    { ReusableObjectKind.Ipv4 => "ipv4_addr", ReusableObjectKind.Ipv6 => "ipv6_addr", ReusableObjectKind.Port => "inet_service", _ => throw new ArgumentException("object.kindInvalid") };
    internal static bool TryIdentity(string name, out Guid id, out int version, out ReusableObjectKind kind)
    {
        id = default; version = 0; kind = default;
        if (!name.StartsWith("nergal_obj_", StringComparison.Ordinal)) { return false; }
        var parts = name[11..].Split('_');
        if (parts.Length != 3 || !Guid.TryParseExact(parts[0], "N", out id) || id == Guid.Empty || id.ToString("N") != parts[0] ||
            !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out version) || version is < 1 or > 64 || version.ToString(CultureInfo.InvariantCulture) != parts[1]) { return false; }
        kind = parts[2] switch { "4" => ReusableObjectKind.Ipv4, "6" => ReusableObjectKind.Ipv6, "p" => ReusableObjectKind.Port, _ => (ReusableObjectKind)(-1) };
        return Enum.IsDefined(kind);
    }
    internal static PolicyObjectReference? Native(PolicyObjectReference? reference) => reference is { NativeSet: true } ? reference : null;
    internal static FilterRule Attach(FilterRule literal, FilterRule intent) => literal with
    { SourceObject = Native(intent.SourceObject), DestinationObject = Native(intent.DestinationObject), DestinationPortObject = Native(intent.DestinationPortObject) };
    internal static DnatRule Attach(DnatRule literal, DnatRule intent) => literal with
    { SourceObject = Native(intent.SourceObject), DestinationObject = Native(intent.DestinationObject), OriginalPortObject = Native(intent.OriginalPortObject) };
    internal static SnatRule Attach(SnatRule literal, SnatRule intent) => literal with
    { SourceObject = Native(intent.SourceObject), DestinationObject = Native(intent.DestinationObject), DestinationPortObject = Native(intent.DestinationPortObject) };
    internal static BridgeFilterRule Attach(BridgeFilterRule literal, BridgeFilterRule intent) => literal with
    { SourceObject = Native(intent.SourceObject), DestinationObject = Native(intent.DestinationObject), DestinationPortObject = Native(intent.DestinationPortObject) };
    internal static IEnumerable<(PolicyObjectReference?, bool)> References(FilterRule? r) => r is null ? [] : new[] { (r.SourceObject, r.Enabled), (r.DestinationObject, r.Enabled), (r.DestinationPortObject, r.Enabled) };
    internal static IEnumerable<(PolicyObjectReference?, bool)> References(DnatRule? r) => r is null ? [] : new[] { (r.SourceObject, r.Enabled), (r.DestinationObject, r.Enabled), (r.OriginalPortObject, r.Enabled) };
    internal static IEnumerable<(PolicyObjectReference?, bool)> References(SnatRule? r) => r is null ? [] : new[] { (r.SourceObject, r.Enabled), (r.DestinationObject, r.Enabled), (r.DestinationPortObject, r.Enabled) };
    internal static IEnumerable<(PolicyObjectReference?, bool)> References(BridgeFilterRule? r) => r is null ? [] : new[] { (r.SourceObject, r.Enabled), (r.DestinationObject, r.Enabled), (r.DestinationPortObject, r.Enabled) };
}

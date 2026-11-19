using System.Collections.Frozen;

namespace Nergal.Core;

/// <summary>An immutable snapshot of a backend's verified semantic capabilities.</summary>
/// <remarks>A declaration does not establish agent availability or authorization.</remarks>
public sealed record BackendCapabilities
{
    /// <summary>Creates a defensive capability snapshot.</summary>
    /// <param name="backendId">A stable, nonempty backend identifier.</param>
    /// <param name="features">Capabilities established by the backend's conformance tests.</param>
    public BackendCapabilities(string backendId, IEnumerable<FirewallFeature> features)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(backendId);
        BackendId = backendId;
        Features = FeatureValidation.Snapshot(features);
    }

    /// <summary>Gets the stable backend identifier.</summary>
    public string BackendId { get; }

    /// <summary>Gets the immutable supported-feature set.</summary>
    public IReadOnlySet<FirewallFeature> Features { get; }
}

internal static class FeatureValidation
{
    internal static FrozenSet<FirewallFeature> Snapshot(IEnumerable<FirewallFeature> features)
    {
        ArgumentNullException.ThrowIfNull(features);
        var snapshot = features.ToFrozenSet();
        foreach (var feature in snapshot)
        {
            if (!Enum.IsDefined(feature))
            {
                throw new ArgumentOutOfRangeException(nameof(features), feature, "Unknown firewall feature.");
            }
        }

        return snapshot;
    }
}

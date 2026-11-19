namespace Nergal.Core;

/// <summary>Explains whether a backend can preserve all requested policy semantics.</summary>
public sealed record BackendCompatibilityReport
{
    internal BackendCompatibilityReport(string backendId, FirewallFeature[] unsupportedFeatures)
    {
        BackendId = backendId;
        UnsupportedFeatures = Array.AsReadOnly(unsupportedFeatures);
    }

    /// <summary>Gets the assessed backend's identifier.</summary>
    public string BackendId { get; }

    /// <summary>Gets missing capabilities in a deterministic order.</summary>
    public IReadOnlyList<FirewallFeature> UnsupportedFeatures { get; }

    /// <summary>Gets whether every requirement is supported; missing semantics fail closed.</summary>
    public bool IsCompatible => UnsupportedFeatures.Count == 0;
}

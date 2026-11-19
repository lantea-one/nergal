namespace Nergal.Core;

/// <summary>Rejects backend selection when required semantics would be lost.</summary>
public static class BackendCompatibilityEvaluator
{
    /// <summary>Compares policy requirements with a defensive backend capability snapshot.</summary>
    /// <param name="requiredFeatures">The semantics the policy actually requires.</param>
    /// <param name="backend">The backend to assess.</param>
    /// <returns>A deterministic report; this method performs no host operations.</returns>
    public static BackendCompatibilityReport Evaluate(
        IEnumerable<FirewallFeature> requiredFeatures,
        BackendCapabilities backend)
    {
        ArgumentNullException.ThrowIfNull(backend);
        var required = FeatureValidation.Snapshot(requiredFeatures);
        var missing = required.Where(feature => !backend.Features.Contains(feature)).Order().ToArray();
        return new BackendCompatibilityReport(backend.BackendId, missing);
    }
}
